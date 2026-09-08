package main

import (
	"os/exec"
	"testing"
)

func TestPBKDFArgumentDecoding(t *testing.T) {
	cmd := exec.Command("/usr/bin/python3", "../../tests/test_pbkdf_args.py", "-v")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("PBKDF argument tests failed: %v\n%s", err, output)
	}
}
