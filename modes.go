package sshexec

import "encoding/binary"

// Opcode represents a PTY mode opcode
type Opcode byte

// List of PTY mode opcodes
const (
	TTYOPEND Opcode = iota // 0     TTY_OP_END  Indicates end of options.
	VINTR                  // 1     VINTR       Interrupt character; 255 if none.
	VQUIT                  // 2     VQUIT       The quit character (sends SIGQUIT signal on POSIX systems).
	VERASE                 // 3     VERASE      Erase the character to left of the cursor.
	VKILL                  // 4     VKILL       Kill the current input line.
	VEOF                   // 5     VEOF        End-of-file character (sends EOF from the terminal).
	VEOL                   // 6     VEOL        End-of-line character in addition to carriage return and/or linefeed.
	VEOL2                  // 7     VEOL2       Additional end-of-line character.
	VSTART                 // 8     VSTART      Continues paused output (normally control-Q).
	VSTOP                  // 9     VSTOP       Pauses output (normally control-S).
	VSUSP                  // 10    VSUSP       Suspends the current program.
	VDSUSP                 // 11    VDSUSP      Another suspend character.
	VREPRINT               // 12    VREPRINT    Reprints the current input line.
	VWERASE                // 13    VWERASE     Erases a word left of cursor.
	VLNEXT                 // 14    VLNEXT      Enter the next character typed literally, even if it is a special character
	VFLUSH                 // 15    VFLUSH      Character to flush output.
	VSWTCH                 // 16    VSWTCH      Switch to a different shell layer.
	VSTATUS                // 17    VSTATUS     Prints system status line (load, command, pid, etc).
	VDISCARD               // 18    VDISCARD    Toggles the flushing of terminal output.
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	IGNPAR  // 30    IGNPAR      The ignore parity flag.
	PARMRK  // 31    PARMRK      Mark parity and framing errors.
	INPCK   // 32    INPCK       Enable checking of parity errors.
	ISTRIP  // 33    ISTRIP      Strip 8th bit off characters.
	INLCR   // 34    INLCR       Map NL into CR on input.
	IGNCR   // 35    IGNCR       Ignore CR on input.
	ICRNL   // 36    ICRNL       Map CR to NL on input.
	IUCLC   // 37    IUCLC       Translate uppercase characters to lowercase.
	IXON    // 38    IXON        Enable output flow control.
	IXANY   // 39    IXANY       Any char will restart after stop.
	IXOFF   // 40    IXOFF       Enable input flow control.
	IMAXBEL // 41    IMAXBEL     Ring bell on input queue full.
	_
	_
	_
	_
	_
	_
	_
	_
	ISIG    // 50    ISIG        Enable signals INTR, QUIT, [D]SUSP.
	ICANON  // 51    ICANON      Canonicalize input lines.
	XCASE   // 52    XCASE       Enable input/output of uppercase characters by preceding their lowercase equivalents with "\".
	ECHO    // 53    ECHO        Enable echoing.
	ECHOE   // 54    ECHOE       Visually erase chars.
	ECHOK   // 55    ECHOK       Kill character discards current line.
	ECHONL  // 56    ECHONL      Echo NL even if ECHO is off.
	NOFLSH  // 57    NOFLSH      Don't flush after interrupt.
	TOSTOP  // 58    TOSTOP      Stop background jobs from output.
	IEXTEN  // 59    IEXTEN      Enable extensions.
	ECHOCTL // 60    ECHOCTL     Echo control characters as ^(Char).
	ECHOKE  // 61    ECHOKE      Visual erase for line kill.
	PENDIN  // 62    PENDIN      Retype pending input.
	_
	_
	_
	_
	_
	_
	_
	OPOST  // 70    OPOST       Enable output processing.
	OLCUC  // 71    OLCUC       Convert lowercase to uppercase.
	ONLCR  // 72    ONLCR       Map NL to CR-NL.
	OCRNL  // 73    OCRNL       Translate carriage return to newline (output).
	ONOCR  // 74    ONOCR       Translate newline to carriage return-newline (output).
	ONLRET // 75    ONLRET      Newline performs a carriage return  (output).
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	CS7               // 90    CS7         7 bit mode.
	CS8               // 91    CS8         8 bit mode.
	PARENB            // 92    PARENB      Parity enable.
	PARODD            // 93    PARODD      Odd parity, else even.
	TTYOPISPEED = 128 // 128 TTY_OP_ISPEED  Specifies the input baud rate in bits per second.
	TTYOPOSPEED = 129 // 129 TTY_OP_OSPEED  Specifies the output baud rate in bits per second.
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
