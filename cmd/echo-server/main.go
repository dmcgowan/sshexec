package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io"
	"io/ioutil"
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
	)

	flag.StringVar(&githubToken, "t", "", "Github access token")
	flag.StringVar(&githubOrg, "o", "", "Github organization")
	flag.StringVar(&githubTeam, "a", "", "Github Team with access")
	flag.StringVar(&githubAdminTeam, "s", "", "Github Team with admin")
	flag.StringVar(&keyFile, "k", "keyfile", "Server private key")
	flag.StringVar(&listenAddr, "l", ":7329", "Listen address")

	flag.Parse()

	ga, err := githubauth.NewGithubAuthorizer(githubToken, githubOrg, githubTeam, githubAdminTeam)
	if err != nil {
		logrus.Fatalf("Failure creating authorizer: %+v", err)
	}

	signer, err := getServerKey(keyFile)
	if err != nil {
		logrus.Fatalf("Key error: %v", err)
	}

	d := sshexec.NewDispatcher(signer, ga)

	d.AddCommand("echo", func(sc *ssh.ServerConn, rw io.ReadWriteCloser) error {
		b, err := ioutil.ReadAll(rw)
		if err != nil {
			return errors.Wrap(err, "failed to read all")
		}

		if _, err := rw.Write(b); err != nil {
			return errors.Wrap(err, "failed to write")
		}

		logrus.Infof("Wrote response for %s", sc.User())

		return nil
	})

	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		logrus.Fatalf("Listen error: %v", err)
	}

	d.Serve(l)
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
