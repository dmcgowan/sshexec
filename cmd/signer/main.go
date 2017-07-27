package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/dmcgowan/sshexec"
	"github.com/dmcgowan/sshexec/githubauth"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
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
		expireDuration  time.Duration
	)

	flag.StringVar(&githubToken, "t", "", "Github access token")
	flag.StringVar(&githubOrg, "o", "", "Github organization")
	flag.StringVar(&githubTeam, "a", "", "Github Team with access")
	flag.StringVar(&githubAdminTeam, "s", "", "Github Team with admin")
	flag.StringVar(&keyFile, "k", "keyfile", "Server private key")
	flag.StringVar(&listenAddr, "l", ":7329", "Listen address")
	flag.StringVar(&cert, "c", "", "CA Certificate")
	flag.StringVar(&certKey, "ck", "", "CA Certificate Key")
	flag.DurationVar(&expireDuration, "x", 30*24*time.Hour, "Duration for certificates to be valid")

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

	d.HandleCommand("sign", func(c ssh.Channel, cs sshexec.ConnectionSettings, ts <-chan sshexec.TerminalSettings) error {
		pemBlock, err := ioutil.ReadAll(c)
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

		if err := validateSubject(cs, csr.Subject); err != nil {
			return errors.Wrap(err, "subject validation failed")
		}

		sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return errors.Wrap(err, "error creating int")
		}

		certTemplate := &x509.Certificate{
			SerialNumber:          sn,
			Subject:               csr.Subject,
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(expireDuration),
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
		}
		cert, err := x509.CreateCertificate(rand.Reader, certTemplate, ca, csr.PublicKey, caKey)
		if err != nil {
			errors.Wrap(err, "error creating certificate")
		}

		certPem := &pem.Block{Type: "CERTIFICATE", Bytes: cert}
		err = pem.Encode(c, certPem)
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

func validateSubject(cs sshexec.ConnectionSettings, subject pkix.Name) error {
	if cs.User != subject.CommonName {
		return errors.Errorf("unexpected common name %q, expected %q", subject.CommonName, cs.User)
	}
	if len(subject.Organization) != 1 || len(subject.OrganizationalUnit) != 1 {
		return errors.Errorf("bad organization information")
	}
	if !githubauth.IsTeamMember(cs.Permissions, subject.Organization[0], subject.OrganizationalUnit[0]) {
		return errors.Errorf("no team membership to %s %s", subject.Organization[0], subject.OrganizationalUnit[0])
	}
	return nil
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
