package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/dmcgowan/sshexec"
	"github.com/dmcgowan/sshexec/githubauth"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

func main() {
	var (
		githubToken     string
		githubOrg       string
		githubTeam      string
		githubAdminTeam string
		keyFile         string
		listenAddr      string
		cert            string
		certKey         string
	)

	flag.StringVar(&githubToken, "t", "", "Github access token")
	flag.StringVar(&githubOrg, "o", "", "Github organization")
	flag.StringVar(&githubTeam, "a", "", "Github Team with access")
	flag.StringVar(&githubAdminTeam, "s", "", "Github Team with admin")
	flag.StringVar(&keyFile, "k", "keyfile", "Server private key")
	flag.StringVar(&listenAddr, "l", ":7329", "Listen address")
	flag.StringVar(&cert, "c", "", "CA Certificate")
	flag.StringVar(&certKey, "ck", "", "CA Certificate Key")

	flag.Parse()

	ga, err := githubauth.NewGithubAuthorizer(githubToken, githubOrg, githubTeam, githubAdminTeam)
	if err != nil {
		logrus.Fatalf("Failure creating authorizer: %+v", err)
	}

	signer, err := getServerKey(keyFile)
	if err != nil {
		logrus.Fatalf("Key error: %+v", err)
	}

	ca, caKey, err := loadCertificate(cert, certKey)
	if err != nil {
		logrus.Fatalf("Error loading certificate: %+v", err)
	}

	d := sshexec.NewDispatcher(signer, ga)

	d.AddCommand("sign", func(sc *ssh.ServerConn, rw io.ReadWriteCloser) error {
		pemBlock, err := ioutil.ReadAll(rw)
		if err != nil {
			return errors.Wrap(err, "failed to read all")
		}

		var csrDERBlock *pem.Block
		csrDERBlock, pemBlock = pem.Decode(pemBlock)
		if csrDERBlock == nil || csrDERBlock.Type != "CERTIFICATE REQUEST" {
			return errors.New("missing certificate request block")
		}

		csr, err := x509.ParseCertificateRequest(csrDERBlock.Bytes)
		if err != nil {
			return errors.Wrap(err, "error parsing certificate request")
		}

		if sc.User() != csr.Subject.CommonName {
			return errors.Errorf("unexpected common name %q, expected %q", csr.Subject.CommonName, sc.User())
		}

		sn, err := rand.Int(rand.Reader, big.NewInt(0xFFFFFFFFFFFF))
		if err != nil {
			return errors.Wrap(err, "error creating int")
		}
		// TODO: Verify extensions
		certTemplate := &x509.Certificate{
			SerialNumber:    sn,
			Subject:         csr.Subject,
			DNSNames:        csr.DNSNames,
			IPAddresses:     csr.IPAddresses,
			EmailAddresses:  csr.EmailAddresses,
			Extensions:      csr.Extensions,
			ExtraExtensions: csr.ExtraExtensions,
		}
		cert, err := x509.CreateCertificate(rand.Reader, certTemplate, ca, csr.PublicKey, caKey)
		if err != nil {
			errors.Wrap(err, "error creating certificate")
		}

		certPem := &pem.Block{Type: "CERTIFICATE", Bytes: cert}
		err = pem.Encode(rw, certPem)
		if err != nil {
			return errors.Wrap(err, "error encoding certificate")
		}

		return nil
	})

	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		logrus.Fatalf("Listen error: %v", err)
	}

	d.Serve(l)
}

func loadCertificate(certFile, keyFile string) (*x509.Certificate, crypto.PrivateKey, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error loading key pair")
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, errors.Wrap(err, "error parsing certificate")
	}

	return x509Cert, cert.PrivateKey, nil

}

func getServerKey(keyFile string) (ssh.Signer, error) {
	b, err := ioutil.ReadFile(keyFile)
	if err == nil {
		return ssh.ParsePrivateKey(b)
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	// Generate new key
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	f, err := os.Create(keyFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	privatePEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	err = pem.Encode(f, privatePEM)
	if err != nil {
		return nil, err
	}

	return ssh.NewSignerFromKey(k)
}
