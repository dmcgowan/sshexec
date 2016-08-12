package sshexec

import (
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type ExecHandler func(*ssh.ServerConn, io.ReadWriteCloser) error

type Dispatcher struct {
	c *ssh.ServerConfig

	commands map[string]ExecHandler
}

func NewDispatcher(serverKey ssh.Signer, auth Authorizer) *Dispatcher {
	c := &ssh.ServerConfig{
		PublicKeyCallback: auth.Authorize,
		AuthLogCallback: func(conn ssh.ConnMetadata, method string, err error) {
			if err != nil && method != "none" {
				logrus.Infof("Auth error (%s): %s : %+v", method, conn.User(), err)
			}
		},
	}

	c.AddHostKey(serverKey)

	return &Dispatcher{
		c:        c,
		commands: map[string]ExecHandler{},
	}
}

func (d *Dispatcher) Serve(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			logrus.Fatalf("Accept error: %v", err)
		}
		go d.handleConn(conn)
	}
}

func (d *Dispatcher) handleConn(conn net.Conn) {
	sc, ncc, rc, err := ssh.NewServerConn(conn, d.c)
	if err != nil {
		logrus.Infof("Server conn error: %s", err)
		return
	}
	defer sc.Close()

	go ssh.DiscardRequests(rc)

	nc := <-ncc

	if nc.ChannelType() != "session" {
		if err := nc.Reject(ssh.UnknownChannelType, "channel not currently supported"); err != nil {
			logrus.Errorf("Reject error: %v", err)
		}
		return
	}
	c, rc, err := nc.Accept()
	if err != nil {
		logrus.Errorf("Accept error: %v", err)
		return
	}

	hchan := make(chan ExecHandler)

	go func() {
		for r := range rc {
			var err error
			var h ExecHandler

			switch r.Type {
			case "env":
				// TODO: Print envs
			case "shell":
				err = errors.New("shell not supported")
			case "exec":
				l := binary.BigEndian.Uint32(r.Payload)
				h, err = d.lookupCommand(string(r.Payload[4 : l+4]))
			default:
				err = errors.Errorf("unknown type: %s", r.Type)
			}

			if r.WantReply {
				if err != nil {
					errMsg := err.Error()
					logrus.Errorf("Request rejected: %+v", errMsg)
					payload := make([]byte, len(errMsg)+4)
					binary.BigEndian.PutUint32(payload, uint32(len(errMsg)))
					copy(payload[4:], errMsg)
					err = r.Reply(false, payload)
				} else {
					err = r.Reply(true, nil)
				}
				if err != nil {
					logrus.Infof("Reply error: %+v", err)
					continue
				}
			} else if err != nil {
				logrus.Infof("Request error: %+v", err)
				continue
			}
			if h != nil {
				hchan <- h
			}

		}
	}()

	h := <-hchan

	var responseStatus uint32
	err = h(sc, c)
	if err != nil {
		logrus.Infof("Command failed: %+v", err)

		// TODO: Check if has status function
		responseStatus = 1
	}

	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, responseStatus)
	if _, err := c.SendRequest("exit-status", false, payload); err != nil {
		logrus.Errorf("Send exit status error: %v", err)
	}

	c.Close()

	// Before closing the connection give client a chance to clean up
	time.Sleep(time.Second)
}

func (d *Dispatcher) AddCommand(name string, h ExecHandler) {
	d.commands[name] = h
}

func (d *Dispatcher) lookupCommand(name string) (ExecHandler, error) {
	cmd, ok := d.commands[name]
	if !ok {
		return nil, errors.Errorf("command %q does not exist", name)
	}

	return cmd, nil
}
