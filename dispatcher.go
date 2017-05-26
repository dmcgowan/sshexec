package sshexec

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/Sirupsen/logrus"
	"github.com/google/shlex"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type ConnectionSettings struct {
	Args        []string
	User        string
	Permissions *ssh.Permissions
	Env         map[string]string
}

type TerminalSettings struct {
	Term          string
	Width, Height uint32
	Modes         map[Opcode]uint32
}

type Handler func(ssh.Channel, ConnectionSettings, <-chan TerminalSettings) error

type Dispatcher struct {
	c *ssh.ServerConfig

	shell    Handler
	commands map[string]Handler
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
		commands: map[string]Handler{},
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

	go func(in <-chan *ssh.Request) {
		for req := range in {
			logrus.Debugf("Discarding: %s", req.Type)
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}(rc)

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

		go d.handleChannelRequests(sc, c, rc)
	}
}

func (d *Dispatcher) handleChannelRequests(sc *ssh.ServerConn, c ssh.Channel, rc <-chan *ssh.Request) {
	settings := ConnectionSettings{
		User:        sc.User(),
		Permissions: sc.Permissions,
		Env:         map[string]string{},
	}
	var tchan chan TerminalSettings
	var handled bool
	for r := range rc {
		var err error
		var h Handler

		switch r.Type {
		case "env":
			if !handled {
				b := r.Payload
				key, b := strVal(b)
				value, b := strVal(b)
				settings.Env[key] = value
			} else {
				err = errors.New("cannot set env after command")
			}
		case "window-change":
			if tchan != nil {
				b := r.Payload
				tw, b := intVal(b)
				th, b := intVal(b)
				_, b = intVal(b) // Terminal width, pixels
				_, b = intVal(b) // Terminal height, pixels
				tchan <- TerminalSettings{
					Width:  tw,
					Height: th,
				}
			} else {
				err = errors.New("window change without pty request")
			}
		case "shell":
			if !handled {
				h = d.shell
			} else {
				err = errors.New("cannot do shell request after command")
			}
		case "pty-req":
			if !handled {
				tchan = make(chan TerminalSettings, 5)
				b := r.Payload
				term, b := strVal(b)
				tw, b := intVal(b)
				th, b := intVal(b)
				_, b = intVal(b) // Terminal width, pixels
				_, b = intVal(b) // Terminal height, pixels
				modes, b := modes(b)
				tchan <- TerminalSettings{
					Term:   term,
					Width:  tw,
					Height: th,
					Modes:  modes,
				}
			} else {
				err = errors.New("cannot do pty request after command")
			}
		case "exec":
			if !handled {
				s, _ := strVal(r.Payload)
				args, err := shlex.Split(s)
				if err != nil {
					err = errors.Wrap(err, "unable to parse exec command")
				} else if len(args) == 0 {
					err = errors.New("no exec command given")
				} else {
					h, err = d.lookupCommand(args[0])
					if err == nil {
						settings.Args = args
					}
				}
			} else {
				err = errors.New("cannot do exec after command")
			}
		default:
			err = errors.Errorf("unhandled type: %s", r.Type)
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
			go h(c, settings, tchan)
			handled = true
		}

	}
}

func wrapHandler(h Handler) Handler {
	return func(c ssh.Channel, cs ConnectionSettings, ts <-chan TerminalSettings) error {
		defer c.Close()

		var responseStatus uint32
		err := h(c, cs, ts)
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
			return err
		}

		return nil
	}
}

// HandleShells calls the given handler with a shell request is received.
func (d *Dispatcher) HandleShell(h Handler) {
	d.shell = wrapHandler(h)
}

// HandleCommand handles exec commands for the provided name.
func (d *Dispatcher) HandleCommand(name string, h Handler) {
	d.commands[name] = wrapHandler(h)
}

func (d *Dispatcher) lookupCommand(name string) (Handler, error) {
	cmd, ok := d.commands[name]
	if !ok {
		return nil, errors.Errorf("command %q does not exist", name)
	}

	return cmd, nil
}

func strVal(b []byte) (string, []byte) {
	if len(b) < 4 {
		return "", b
	}
	l := binary.BigEndian.Uint32(b)
	if len(b) < int(l)+4 {
		return "", b
	}
	return string(b[4 : l+4]), b[l+4:]
}

func intVal(b []byte) (uint32, []byte) {
	if len(b) < 4 {
		return 0, b
	}
	return binary.BigEndian.Uint32(b), b[4:]
}
