package sshexec

import "golang.org/x/crypto/ssh"

type Authorizer interface {
	Authorize(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error)
}
