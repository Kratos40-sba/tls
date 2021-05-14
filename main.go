package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
)

func main()  {
	tlsServer , tlsClient , err := setupCA()
	if err != nil {
		log.Fatalln(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter , r *http.Request) {
		_,_ = fmt.Fprintln(w , "TLS")
	}))
	server.TLS = tlsServer
	server.StartTLS()
	defer server.Close()
	transport := &http.Transport{
		TLSClientConfig: tlsClient,
	}
	httpClient := http.Client{
		Transport: transport,
	}
	response , err := httpClient.Get(server.URL)
	if err != nil {
		log.Fatalln(err)
	}
	resBody , err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatalln(err)
	}
	b := strings.TrimSpace(string(resBody[:]))
	if b == "TLS"{
		log.Println(b)
	}else {
		log.Println("TLS IS NOT WORKING !!")
	}


}

// creation de Certification "CA"
func setupCA() (tlsConfig , tlsClient *tls.Config , err error) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2021),
		Subject: pkix.Name{
			Organization: []string{"ESI-SBA"},
			Country: []string{"DZ"},
			Locality: []string{"Sidi Bel Abbes"},
			PostalCode: []string{"22000"},
		},
		NotBefore: time.Now(),
		NotAfter: time.Now().AddDate(0,0,3),
		IsCA: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth,x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	// private/public key creation
	caPrivateKey , err := rsa.GenerateKey(rand.Reader,4096)
	if err != nil {
		return nil,nil,err
	}
	// CA creation
	caBytes , err := x509.CreateCertificate(rand.Reader,ca , ca ,&caPrivateKey.PublicKey,caPrivateKey)
	if err != nil {
		return nil,nil,err
	}
	// pem encode
	caPEM := new(bytes.Buffer)
	_ = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	caPrivateKeyPEM := new(bytes.Buffer)
	_ = pem.Encode(caPrivateKeyPEM,&pem.Block{
		Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivateKey),
	})
	// certificate server
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2021),
		Subject: pkix.Name{
			Organization: []string{"ESI-SBA"},
			Country: []string{"DZ"},
			Locality: []string{"Sidi Bel Abbes"},
			PostalCode: []string{"22000"},
		},
		IPAddresses: []net.IP{net.IPv4(127,0,0,1)},
		NotBefore: time.Now(),
		NotAfter: time.Now().AddDate(0,0,3),
		SubjectKeyId: []byte{1,2,3,4,6},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth,x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}

	certPrivateKey , err := rsa.GenerateKey(rand.Reader,4096)
	if err != nil {
		return nil, nil, err
	}
	certBytes , err := x509.CreateCertificate(rand.Reader, cert , ca , &certPrivateKey.PublicKey , caPrivateKey)
	if err != nil {
		return nil, nil, err
	}
	certPEM := new(bytes.Buffer)
	_ = pem.Encode(certPEM, &pem.Block{
		Type: "CERTIFICATE",
		Bytes: certBytes,
	})
	certPrivateKeyPEM := new(bytes.Buffer)
	_ = pem.Encode(certPrivateKeyPEM,&pem.Block{
		Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivateKey),
	})
	certServer , err := tls.X509KeyPair(certPEM.Bytes(),certPrivateKeyPEM.Bytes())
	if err != nil {
		return nil, nil, err
	}
	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{certServer},
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caPEM.Bytes())
	tlsClient = &tls.Config{
		RootCAs: certPool,
	}
	return
}
