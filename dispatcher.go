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
	User        string
	Permissions *ssh.Permissions
	Env         map[string]string
}

type TerminalSettings struct {
	Term          string
	Width, Height uint32
	Modes         map[Opcode]uint32
}
type ExecHandler func([]string, io.ReadWriteCloser, ConnectionSettings) error

type ShellHandler func(ssh.Channel, ConnectionSettings, <-chan TerminalSettings)

type Dispatcher struct {
	c *ssh.ServerConfig

	shell    ShellHandler
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
	env := map[string]string{}

	tchan := make(chan TerminalSettings, 5)
	for r := range rc {
		var err error
		var h func(*ssh.ServerConn, io.ReadWriteCloser) error
		var envc map[string]string

		switch r.Type {
		case "env":
			b := r.Payload
			key, b := strVal(b)
			value, b := strVal(b)
			env[key] = value
		case "window-change":
			b := r.Payload
			tw, b := intVal(b)
			th, b := intVal(b)
			_, b = intVal(b) // Terminal width, pixels
			_, b = intVal(b) // Terminal height, pixels
			tchan <- TerminalSettings{
				Width:  tw,
				Height: th,
			}
		case "shell":
			envc = env
		case "pty-req":
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
		case "exec":
			s, _ := strVal(r.Payload)
			args, err := shlex.Split(s)
			if err != nil {
				err = errors.Wrap(err, "unable to parse exec command")
			} else if len(args) == 0 {
				err = errors.New("no exec command given")
			} else {
				var f ExecHandler
				f, err = d.lookupCommand(args[0])
				if err == nil {
					envc = env
					env = map[string]string{}
					h = func(sc *ssh.ServerConn, rw io.ReadWriteCloser) error {
						return f(args, rw, ConnectionSettings{
							User:        sc.User(),
							Permissions: sc.Permissions,
							Env:         envc,
						})
					}
				}
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
			go func() {
				defer c.Close()

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
		} else if envc != nil {
			go d.shell(c, ConnectionSettings{
				User:        sc.User(),
				Permissions: sc.Permissions,
				Env:         envc,
			}, tchan)

		}

	}
}

func (d *Dispatcher) ShellHandler(h ShellHandler) {
	d.shell = h
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

type Opcode byte

const (
	TTYOPEND    Opcode = iota // 0     TTY_OP_END  Indicates end of options.
	VINTR                     // 1     VINTR       Interrupt character; 255 if none.
	VQUIT                     // 2     VQUIT       The quit character (sends SIGQUIT signal on POSIX systems).
	VERASE                    // 3     VERASE      Erase the character to left of the cursor.
	VKILL                     // 4     VKILL       Kill the current input line.
	VEOF                      // 5     VEOF        End-of-file character (sends EOF from the terminal).
	VEOL                      // 6     VEOL        End-of-line character in addition to carriage return and/or linefeed.
	VEOL2                     // 7     VEOL2       Additional end-of-line character.
	VSTART                    // 8     VSTART      Continues paused output (normally control-Q).
	VSTOP                     // 9     VSTOP       Pauses output (normally control-S).
	VSUSP                     // 10    VSUSP       Suspends the current program.
	VDSUSP                    // 11    VDSUSP      Another suspend character.
	VREPRINT                  // 12    VREPRINT    Reprints the current input line.
	VWERASE                   // 13    VWERASE     Erases a word left of cursor.
	VLNEXT                    // 14    VLNEXT      Enter the next character typed literally, even if it is a special character
	VFLUSH                    // 15    VFLUSH      Character to flush output.
	VSWTCH                    // 16    VSWTCH      Switch to a different shell layer.
	VSTATUS                   // 17    VSTATUS     Prints system status line (load, command, pid, etc).
	VDISCARD                  // 18    VDISCARD    Toggles the flushing of terminal output.
	IGNPAR      = 30          // 30    IGNPAR      The ignore parity flag.
	PARMRK                    // 31    PARMRK      Mark parity and framing errors.
	INPCK                     // 32    INPCK       Enable checking of parity errors.
	ISTRIP                    // 33    ISTRIP      Strip 8th bit off characters.
	INLCR                     // 34    INLCR       Map NL into CR on input.
	IGNCR                     // 35    IGNCR       Ignore CR on input.
	ICRNL                     // 36    ICRNL       Map CR to NL on input.
	IUCLC                     // 37    IUCLC       Translate uppercase characters to lowercase.
	IXON                      // 38    IXON        Enable output flow control.
	IXANY                     // 39    IXANY       Any char will restart after stop.
	IXOFF                     // 40    IXOFF       Enable input flow control.
	IMAXBEL                   // 41    IMAXBEL     Ring bell on input queue full.
	ISIG        = 40          // 50    ISIG        Enable signals INTR, QUIT, [D]SUSP.
	ICANON                    // 51    ICANON      Canonicalize input lines.
	XCASE                     // 52    XCASE       Enable input and output of uppercase characters by preceding their lowercase equivalents with "\".
	ECHO                      // 53    ECHO        Enable echoing.
	ECHOE                     // 54    ECHOE       Visually erase chars.
	ECHOK                     // 55    ECHOK       Kill character discards current line.
	ECHONL                    // 56    ECHONL      Echo NL even if ECHO is off.
	NOFLSH                    // 57    NOFLSH      Don't flush after interrupt.
	TOSTOP                    // 58    TOSTOP      Stop background jobs from output.
	IEXTEN                    // 59    IEXTEN      Enable extensions.
	ECHOCTL                   // 60    ECHOCTL     Echo control characters as ^(Char).
	ECHOKE                    // 61    ECHOKE      Visual erase for line kill.
	PENDIN                    // 62    PENDIN      Retype pending input.
	OPOST       = 70          // 70    OPOST       Enable output processing.
	OLCUC                     // 71    OLCUC       Convert lowercase to uppercase.
	ONLCR                     // 72    ONLCR       Map NL to CR-NL.
	OCRNL                     // 73    OCRNL       Translate carriage return to newline (output).
	ONOCR                     // 74    ONOCR       Translate newline to carriage return-newline (output).
	ONLRET                    // 75    ONLRET      Newline performs a carriage return  (output).
	CS7         = 90          // 90    CS7         7 bit mode.
	CS8                       // 91    CS8         8 bit mode.
	PARENB                    // 92    PARENB      Parity enable.
	PARODD                    // 93    PARODD      Odd parity, else even.
	TTYOPISPEED = 128         // 128 TTY_OP_ISPEED  Specifies the input baud rate in bits per second.
	TTYOPOSPEED               // 129 TTY_OP_OSPEED  Specifies the output baud rate in bits per second.
)

func modes(b []byte) (map[Opcode]uint32, []byte) {
	if len(b) < 4 {
		return nil, b
	}
	l := binary.BigEndian.Uint32(b)
	if len(b) < int(l)+4 {
		return nil, b
	}
	s := b[4 : l+4]
	b = b[l+4:]

	m := map[Opcode]uint32{}
	for len(s) > 5 && s[0] > 0x00 && s[0] < 160 {
		m[Opcode(s[0])], s = intVal(s[1:])
	}
	return m, b
}
