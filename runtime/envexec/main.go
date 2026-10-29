package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "install":
		if len(args) != 2 {
			usage()
			return 2
		}
		self, err := os.Executable()
		if err == nil {
			err = install(self, args[1])
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "envexec install: %v\n", err)
			return 1
		}
		return 0
	case "probe":
		if len(args) != 2 {
			usage()
			return 2
		}
		if err := probe(args[1], 3*time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "envexec probe: %v\n", err)
			return 1
		}
		return 0
	case "private":
		if len(args) < 4 || args[2] != "--" {
			usage()
			return 2
		}
		if err := privateDir(args[1], os.Geteuid()); err != nil {
			fmt.Fprintf(os.Stderr, "envexec private: %v\n", err)
			return 1
		}
		return execCommand(args[3:], os.Environ())
	}
	opts, err := parseRunArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "envexec: %v\n", err)
		usage()
		return 2
	}
	if err := waitReady(opts.Ready, opts.Timeout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "envexec: %v\n", err)
		return 1
	}
	secrets, err := loadSecrets(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "envexec: %v\n", err)
		return 1
	}
	return execCommand(opts.Command, buildEnv(os.Environ(), secrets))
}

// execCommand replaces envexec with the command, so it keeps PID 1 and
// receives the container's signals itself.
func execCommand(command, env []string) int {
	bin, err := exec.LookPath(command[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "envexec: %v\n", err)
		return 127
	}
	err = syscall.Exec(bin, command, env)
	fmt.Fprintf(os.Stderr, "envexec: exec %s: %v\n", bin, err)
	return 126
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  envexec --app <id> [--secret NAME]... [--optional-secret NAME]... [--secrets-dir DIR] [--ready PATH] [--timeout DUR] -- <cmd> [args...]
  envexec install <dir>
  envexec probe <tcp://host:port | http://host:port/path>
  envexec private <dir> -- <cmd> [args...]
`)
}
