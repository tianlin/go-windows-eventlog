//go:build windows && (amd64 || arm64)

package etw

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestNativeOrphanChild(t *testing.T) {
	if os.Getenv("ETW_ORPHAN_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	s, err := New(nil, func(Event) {})
	if s != nil {
		defer s.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("SESSION " + windows.UTF16ToString(s.name))
	// Parent kills us without running deferred cleanup, just like a crash.
	io.Copy(io.Discard, os.Stdin)
}

func startOrphanChild(t *testing.T) (string, func()) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestNativeOrphanChild$")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Env = append(os.Environ(), "ETW_ORPHAN_CHILD=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	kill := func() {
		if stopped {
			return
		}
		stopped = true
		cmd.Process.Kill()
		cmd.Wait()
		stdin.Close()
	}
	t.Cleanup(kill)
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if name, ok := strings.CutPrefix(scanner.Text(), "SESSION "); ok {
				ready <- name
				return
			}
		}
		ready <- ""
	}()
	select {
	case name := <-ready:
		if name == "" {
			t.Fatal("ETW child failed to create session")
		}
		// Exact-name fallback cleanup keeps a failing regression from leaking.
		t.Cleanup(func() {
			kill()
			if err := (windowsOrphanAPI{}).stop(name); err != nil {
				t.Error(err)
			}
		})
		return name, kill
	case <-time.After(15 * time.Second):
		t.Fatal("ETW child startup timed out")
	}
	return "", nil
}

func TestNativeOrphanRecovery(t *testing.T) {
	if os.Getenv("ETW_INTEGRATION") != "1" {
		t.Skip("set ETW_INTEGRATION=1 in an elevated shell")
	}
	liveName, _ := startOrphanChild(t)
	query := func(name string) windows.Errno {
		n, _ := windows.UTF16FromString(name)
		_, code := (windowsTraceAPI{}).control(0, n, 0)
		return code
	}
	for i := 0; i < 3; i++ {
		deadName, kill := startOrphanChild(t)
		kill()
		if code := query(deadName); code != 0 {
			t.Fatalf("crash did not leave expected orphan: %v", code)
		}
		s, err := New(nil, func(Event) {})
		if s != nil {
			t.Cleanup(func() {
				if err := s.Close(); err != nil {
					t.Error(err)
				}
			})
		}
		if err != nil {
			t.Fatal(err)
		}
		if code := query(deadName); code != windows.ERROR_WMI_INSTANCE_NOT_FOUND {
			t.Fatalf("orphan survived recovery: %v", code)
		}
		if code := query(liveName); code != 0 {
			t.Fatalf("recovery stopped live instance: %v", code)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
