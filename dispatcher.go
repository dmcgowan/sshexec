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

type ConnectionSettings struct {
	Args        []string
	User        string
	Permissions *ssh.Permissions
	Env         map[string]string
	Client      string
}

type TerminalSettings struct {
	Term          string
	Width, Height uint32
	Modes         map[Opcode]uint32
}

type Handler func(ssh.Channel, ConnectionSettings, <-chan TerminalSettings) error

// ForwardDial connects to an address
//  - "tcp://<host>:<port>" for connecting to a TCP location
//  - "unix://<path>" for connecting to a unix socket
type ForwardDial func(string, ConnectionSettings) (net.Conn, error)

type Dispatcher struct {
	c *ssh.ServerConfig

	shell    Handler
	commands map[string]Handler
	forwards map[string]ForwardDial
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
		forwards: map[string]ForwardDial{},
	}
}

// Serve accepts and handles connections from the listener.
func (d *Dispatcher) Serve(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			logrus.Fatalf("Accept error: %v", err)
		}
		go d.handleConn(conn)
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

// HandleForwards registers a dial function for specified address. If
// the address is empty it will be called for all addresses which do not
// have a more specific match.
func (d *Dispatcher) HandleForward(address string, h ForwardDial) {
	d.forwards[address] = h
}

func discardRequests(in <-chan *ssh.Request) {
	for req := range in {
		logrus.Debugf("Discarding: %s", req.Type)
		if req.WantReply {
			req.Reply(false, nil)
		}
	}
}

func (d *Dispatcher) handleConn(conn net.Conn) {
	sc, ncc, rc, err := ssh.NewServerConn(conn, d.c)
	if err != nil {
		logrus.Infof("Server conn error: %s", err)
		return
	}
	defer sc.Close()

	go discardRequests(rc)

	for nc := range ncc {
		switch nc.ChannelType() {
		case "session":
			c, rc, err := nc.Accept()
			if err != nil {
				logrus.Errorf("Accept error: %v", err)
				break
			}

			go d.handleChannelRequests(sc, c, rc)
		case "direct-tcpip":
			host, b := strVal(nc.ExtraData())
			hostP, b := intVal(b)
			orig, b := strVal(b)
			origP, b := intVal(b)

			address := fmt.Sprintf("tcp://%s:%d", host, hostP)
			logrus.Debugf("Forward requested to %s from %s:%d", address, orig, origP)

			go d.handleForward(sc, nc, address)

		// OpenSSH defined extension for connecting to a unix socket
		// see https://github.com/openssh/openssh-portable/blob/master/PROTOCOL
		case "direct-streamlocal@openssh.com":
			socketPath, _ := strVal(nc.ExtraData())

			address := fmt.Sprintf("unix://%s", socketPath)
			logrus.Debugf("Forward requested to %s", address)

			go d.handleForward(sc, nc, address)
		default:
			logrus.Debugf("Rejecting channel type: %s", nc.ChannelType())
			if err := nc.Reject(ssh.UnknownChannelType, "channel not currently supported"); err != nil {
				logrus.Errorf("Reject error: %v", err)
			}
		}
	}
}

func (d *Dispatcher) handleChannelRequests(sc *ssh.ServerConn, c ssh.Channel, rc <-chan *ssh.Request) {
	settings := ConnectionSettings{
		User:        sc.User(),
		Permissions: sc.Permissions,
		Env:         map[string]string{},
		Client:      string(sc.ClientVersion()),
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

func (d *Dispatcher) handleForward(sc *ssh.ServerConn, nc ssh.NewChannel, address string) {
	var h ForwardDial
	if ah, ok := d.forwards[address]; ok {
		h = ah
	} else if dh, ok := d.forwards[""]; ok {
		h = dh
	}

	if h == nil {
		if err := nc.Reject(ssh.Prohibited, "connection to host not allowed"); err != nil {
			logrus.Errorf("Reject error: %v", err)
		}
		return
	}

	cs := ConnectionSettings{
		User:        sc.User(),
		Permissions: sc.Permissions,
	}

	conn, err := h(address, cs)
	if err != nil {
		if err := nc.Reject(ssh.ConnectionFailed, "connection to host failed"); err != nil {
			logrus.Errorf("Forward connection error: %v", err)
		}
		return
	}
	defer conn.Close()

	c, rc, err := nc.Accept()
	if err != nil {
		logrus.Errorf("Accept error: %v", err)
		return
	}
	defer c.Close()

	go discardRequests(rc)

	downErr := make(chan error, 1)
	upErr := make(chan error, 1)

	go func() {
		_, err := io.Copy(c, conn)
		downErr <- err

	}()

	go func() {
		_, err := io.Copy(conn, c)
		upErr <- err
	}()

	select {
	case err := <-downErr:
		c.CloseWrite()
		if err != nil {
			logrus.Debugf("Copy error sending down: %v", err)
		}
	case err := <-upErr:
		if err != nil {
			logrus.Debugf("Copy error sending up: %v", err)
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
		c.CloseWrite()

		payload := make([]byte, 4)
		binary.BigEndian.PutUint32(payload, responseStatus)
		if _, err := c.SendRequest("exit-status", false, payload); err != nil {
			logrus.Errorf("Send exit status error: %v", err)
			return err
		}

		return nil
	}
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
