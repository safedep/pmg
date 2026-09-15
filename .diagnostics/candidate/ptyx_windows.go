//go:build windows

package ptyx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

type winSession struct {
	con       *ConPty
	stdin     *os.File
	stdout    *os.File
	pid       int
	mu        sync.Mutex
	process   windows.Handle
	thread    windows.Handle
	job       windows.Handle
	killed    uint32
	done      chan struct{}
	waitDone  chan struct{}
	waitErr   error
	exitCode  uint32
	closeOnce sync.Once
	conOnce   sync.Once
	conErr    error
}

func buildCommandLine(prog string, args []string) string {
	allArgs := make([]string, 0, 1+len(args))
	allArgs = append(allArgs, prog)
	allArgs = append(allArgs, args...)
	var b strings.Builder
	for i, v := range allArgs {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(windows.EscapeArg(v))
	}
	return b.String()
}

func buildEnvBlock(env []string) []uint16 {
	if len(env) == 0 {
		return nil
	}
	cleanEnv := make([]string, 0, len(env))
	for _, s := range env {
		if !strings.ContainsRune(s, 0) {
			cleanEnv = append(cleanEnv, s)
		}
	}
	blockStr := strings.Join(cleanEnv, "\x00") + "\x00\x00"
	return utf16.Encode([]rune(blockStr))
}

func Spawn(ctx context.Context, opts SpawnOpts) (Session, error) {
	if opts.CmdLine != "" && len(opts.Args) > 0 {
		return nil, ErrCmdLineWithArgs
	}

	con, err := NewConPty(opts.Cols, opts.Rows, 0)
	if err != nil {
		return nil, err
	}
	var spawnErr error
	defer func() {
		if spawnErr != nil {
			_ = con.Close()
		}
	}()

	progPath, err := exec.LookPath(opts.Prog)
	if err != nil {
		spawnErr = err
		return nil, err
	}

	cmdline := opts.CmdLine
	if cmdline == "" {
		cmdline = buildCommandLine(progPath, opts.Args)
	}

	siEx := new(windows.StartupInfoEx)
	siEx.Cb = uint32(unsafe.Sizeof(*siEx))
	siEx.Flags = windows.STARTF_USESTDHANDLES
	siEx.ProcThreadAttributeList = con.attrList.List()

	pi := new(windows.ProcessInformation)

	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT |
		windows.EXTENDED_STARTUPINFO_PRESENT |
		windows.CREATE_NEW_PROCESS_GROUP)

	pCmdline, err := windows.UTF16PtrFromString(cmdline)
	if err != nil {
		spawnErr = fmt.Errorf("failed to convert command line to UTF16: %w", err)
		return nil, spawnErr
	}

	var pDir *uint16
	if opts.Dir != "" {
		pDir, err = windows.UTF16PtrFromString(opts.Dir)
		if err != nil {
			spawnErr = fmt.Errorf("failed to convert directory to UTF16: %w", err)
			return nil, spawnErr
		}
	}

	var env []string
	if opts.Env != nil {
		env = opts.Env
	} else {
		env = os.Environ()
	}
	envBlock := buildEnvBlock(env)
	var pEnv *uint16
	if len(envBlock) > 0 {
		pEnv = &envBlock[0]
	}

	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		spawnErr = fmt.Errorf("CreateJobObject: %w", err)
		return nil, spawnErr
	}

	ext := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	_, err = windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&ext)),
		uint32(unsafe.Sizeof(ext)),
	)
	if err != nil {
		windows.CloseHandle(job)
		spawnErr = fmt.Errorf("SetInformationJobObject: %w", err)
		return nil, spawnErr
	}

	if err = windows.CreateProcess(
		nil,
		pCmdline,
		nil,
		nil,
		false,
		flags,
		pEnv,
		pDir,
		&siEx.StartupInfo,
		pi,
	); err != nil {
		windows.CloseHandle(job)
		spawnErr = fmt.Errorf("failed to create process: %w", err)
		return nil, spawnErr
	}

	if err = windows.AssignProcessToJobObject(job, pi.Process); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		_ = windows.CloseHandle(pi.Thread)
		_ = windows.CloseHandle(pi.Process)
		_ = windows.CloseHandle(job)
		spawnErr = fmt.Errorf("AssignProcessToJobObject: %w", err)
		return nil, spawnErr
	}

	sess := &winSession{
		con:      con,
		stdin:    con.inFile,
		stdout:   con.outFile,
		pid:      int(pi.ProcessId),
		process:  pi.Process,
		thread:   pi.Thread,
		job:      job,
		done:     make(chan struct{}),
		waitDone: make(chan struct{}),
	}

	go func() {
		select {
		case <-ctx.Done():
			_ = sess.Kill()
		case <-sess.done:
		}
	}()

	go sess.waitProcess(pi.Process)

	return sess, nil
}

func (s *winSession) PtyReader() io.Reader        { return s.stdout }
func (s *winSession) PtyWriter() io.Writer        { return s.stdin }
func (s *winSession) Resize(cols, rows int) error { return s.con.resize(cols, rows) }
func (s *winSession) Pid() int                    { return s.pid }

func (s *winSession) Wait() error {
	<-s.waitDone
	if s.waitErr != nil {
		return s.waitErr
	}
	code := s.exitCode
	if atomic.LoadUint32(&s.killed) == 1 {
		if code == 0 {
			code = 1
		}
	}
	if code == 0 {
		return nil
	}
	return &ExitError{ExitCode: int(code), waitStatus: nil}
}

func (s *winSession) closeCon() error {
	s.conOnce.Do(func() { s.conErr = s.con.Close() })
	return s.conErr
}

func (s *winSession) Kill() error {
	s.mu.Lock()
	if s.process == 0 {
		s.mu.Unlock()
		return nil
	}
	atomic.StoreUint32(&s.killed, 1)
	if s.job != 0 {
		windows.CloseHandle(s.job)
		s.job = 0
	}
	_ = windows.TerminateProcess(s.process, 1)
	st, _ := windows.WaitForSingleObject(s.process, 1500)
	s.mu.Unlock()
	if st == uint32(windows.WAIT_TIMEOUT) {
		go func() { _ = s.closeCon() }()
	}
	return nil
}

func (s *winSession) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.mu.Lock()
		close(s.done)
		process, thread := s.process, s.thread
		s.process, s.thread = 0, 0
		if s.job != 0 {
			windows.CloseHandle(s.job)
			s.job = 0
		}
		_ = windows.TerminateProcess(process, 1)
		s.mu.Unlock()
		// Console cleanup can wait for a reader that needs to call Kill.
		err = s.closeCon()
		releaseHandles := func() {
			<-s.waitDone
			_ = windows.CloseHandle(process)
			_ = windows.CloseHandle(thread)
		}
		select {
		case <-s.waitDone:
			releaseHandles()
		default:
			// Keep the waiter's handles valid without blocking Close on exit.
			go releaseHandles()
		}
	})
	return err
}

func (s *winSession) CloseStdin() error {
	if s == nil || s.stdin == nil {
		return nil
	}
	err := s.stdin.Close()
	if errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}

func (s *winSession) waitProcess(process windows.Handle) {
	st, err := windows.WaitForSingleObject(process, windows.INFINITE)
	if err == nil {
		if st != windows.WAIT_OBJECT_0 {
			err = fmt.Errorf("unexpected wait status: %d", st)
		} else {
			err = windows.GetExitCodeProcess(process, &s.exitCode)
		}
	}
	s.waitErr = err
	close(s.waitDone)
	_ = s.closeCon()
}
