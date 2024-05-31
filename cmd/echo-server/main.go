package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"net"
	"os"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"

	"github.com/dmcgowan/sshexec"
	"github.com/dmcgowan/sshexec/githubauth"
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

	ctx := context.Background()

	var teams []string
	if githubTeam != "" {
		teams = append(teams, githubTeam)
	}
	if githubAdminTeam != "" {
		teams = append(teams, githubAdminTeam)
	}
	ga, err := githubauth.NewGithubAuthorizer(ctx, githubToken, githubOrg, teams...)
	if err != nil {
		logrus.Fatalf("Failure creating authorizer: %+v", err)
	}

	signer, err := getServerKey(keyFile)
	if err != nil {
		logrus.Fatalf("Key error: %v", err)
	}

	d := sshexec.NewDispatcher(signer, ga)

	d.HandleCommand("echo", func(c ssh.Channel, cs sshexec.ConnectionSettings, ts <-chan sshexec.TerminalSettings) error {
		b, err := ioutil.ReadAll(c)
		if err != nil {
			return errors.Wrap(err, "failed to read all")
		}

		if _, err := c.Write(b); err != nil {
			return errors.Wrap(err, "failed to write")
		}

		logrus.Infof("Wrote response for %s", cs.User)

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
