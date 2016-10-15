package sshexec

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/Sirupsen/logrus"
	"github.com/google/shlex"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type ExecHandler func([]string, *ssh.ServerConn, io.ReadWriteCloser) error

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

	for nc := range ncc {
		if nc.ChannelType() != "session" {
			logrus.Debugf("Rejecting channel type: %s", nc.ChannelType())
			if err := nc.Reject(ssh.UnknownChannelType, "channel not currently supported"); err != nil {
				logrus.Errorf("Reject error: %v", err)
			}
			continue
		}

		c, rc, err := nc.Accept()
		if err != nil {
			logrus.Errorf("Accept error: %v", err)
			break
		}

		hchan := make(chan execHandler)

		go d.handleChannelRequests(rc, hchan)

		go func() {
			defer c.Close()

			h := <-hchan

			var responseStatus uint32
			err = h(sc, closeChannelWriter{c})
			if err != nil {
				logrus.Debugf("Command failed: %+v", err)

				fmt.Fprintf(c.Stderr(), "Command failed: %v\n", err)

				// TODO: Check if has status function
				responseStatus = 1
			}

			payload := make([]byte, 4)
			binary.BigEndian.PutUint32(payload, responseStatus)
			if _, err := c.SendRequest("exit-status", false, payload); err != nil {
				logrus.Errorf("Send exit status error: %v", err)
			}
		}()
	}
}

type execHandler func(*ssh.ServerConn, io.ReadWriteCloser) error

func (d *Dispatcher) handleChannelRequests(rc <-chan *ssh.Request, hchan chan<- execHandler) {
	for r := range rc {
		var err error
		var h func(*ssh.ServerConn, io.ReadWriteCloser) error

		switch r.Type {
		case "env":
			// TODO: Print envs
		case "shell":
			err = errors.New("shell not supported")
		case "exec":
			l := binary.BigEndian.Uint32(r.Payload)
			args, err := shlex.Split(string(r.Payload[4 : l+4]))
			if err != nil {
				err = errors.Wrap(err, "unable to parse exec command")
			} else if len(args) == 0 {
				err = errors.New("no exec command given")
			} else {
				var f ExecHandler
				f, err = d.lookupCommand(args[0])
				if err == nil {
					h = func(sc *ssh.ServerConn, rw io.ReadWriteCloser) error {
						return f(args, sc, rw)
					}
				}
			}
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

type closeChannelWriter struct {
	ssh.Channel
}

func (c closeChannelWriter) Close() error {
	return c.CloseWrite()
}
