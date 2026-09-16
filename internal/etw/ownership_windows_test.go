//go:build windows && (amd64 || arm64)

package etw

import (
	"errors"
	"os"
	"reflect"
	"testing"

	"golang.org/x/sys/windows"
)

type orphanFixture struct {
	names   []string
	stopped []string
	stopErr error
}

func (a *orphanFixture) list() ([]string, error) { return a.names, nil }
func (a *orphanFixture) exited(pid uint32, created uint64) (bool, error) {
	switch pid {
	case 100:
		return true, nil // exited
	case 200:
		return created != 20, nil // live, but older creation time means PID reuse
	default:
		return false, windows.ERROR_ACCESS_DENIED
	}
}
func (a *orphanFixture) stop(name string) error {
	a.stopped = append(a.stopped, name)
	return a.stopErr
}

func TestOrphanRecoveryPreservesLiveAndUnverifiableOwners(t *testing.T) {
	prefix := "go-windows-eventlog-v1-test-"
	a := &orphanFixture{names: []string{
		prefix + "100-a-1", prefix + "200-14-1", prefix + "200-13-2", prefix + "300-a-1",
		"go-windows-eventlog-v1-other-100-a-1", "go-windows-eventlog-{old-guid}",
		prefix + "0-a-1", prefix + "100-0-1", prefix + "100-a-0", prefix + "100-a-1-extra", prefix + "bad",
	}}
	if err := recoverOrphans(prefix, a); err != nil {
		t.Fatal(err)
	}
	if want := []string{prefix + "100-a-1", prefix + "200-13-2"}; !reflect.DeepEqual(a.stopped, want) {
		t.Fatalf("stopped %v; want %v", a.stopped, want)
	}
}

func TestOrphanRecoveryReportsStopFailure(t *testing.T) {
	a := &orphanFixture{names: []string{"owned-100-a-1"}, stopErr: windows.ERROR_ACCESS_DENIED}
	if err := recoverOrphans("owned-", a); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("lost stop error: %v", err)
	}
}

func TestProcessIdentityDetectsPIDReuse(t *testing.T) {
	created, _, err := processIdentity(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	a := windowsOrphanAPI{}
	if dead, err := a.exited(uint32(os.Getpid()), created); err != nil || dead {
		t.Fatalf("live process considered dead: %v %v", dead, err)
	}
	if dead, err := a.exited(uint32(os.Getpid()), created-1); err != nil || !dead {
		t.Fatalf("reused PID not detected: %v %v", dead, err)
	}
}
