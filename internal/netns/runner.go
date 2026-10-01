package netns

import (
	"bytes"
	"fmt"
	"os/exec"
)

// Runner executes a system command and returns its combined output. It
// exists so Manager's orchestration logic can be unit-tested against a fake
// without needing root or real network namespaces.
type Runner interface {
	Run(name string, args ...string) (output []byte, err error)
	RunStdin(name string, stdin string, args ...string) (output []byte, err error)
}

// execRunner is the real Runner, backed by os/exec.
type execRunner struct{}

func (execRunner) Run(name string, args ...string) ([]byte, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return out, commandError(name, args, out, err)
	}
	return out, nil
}

func (execRunner) RunStdin(name string, stdin string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.Stdin = bytes.NewReader([]byte(stdin))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, commandError(name, args, out, err)
	}
	return out, nil
}

func commandError(name string, args []string, out []byte, err error) error {
	if msg := bytes.TrimSpace(out); len(msg) > 0 {
		return fmt.Errorf("%s %v: %s", name, args, msg)
	}
	return fmt.Errorf("%s %v: %w", name, args, err)
}
