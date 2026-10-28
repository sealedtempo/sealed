package app

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// readSecretTTY prompts on stderr and reads one line from the terminal with echo off (stty), so the value never
// shows on screen or in shell history.
func readSecretTTY(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	off := exec.Command("stty", "-echo")
	off.Stdin = os.Stdin
	echoOff := off.Run() == nil
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if echoOff {
		on := exec.Command("stty", "echo")
		on.Stdin = os.Stdin
		_ = on.Run()
	}
	fmt.Fprintln(os.Stderr)
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
