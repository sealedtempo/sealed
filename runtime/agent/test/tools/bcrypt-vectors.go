//go:build ignore

// Prints bcrypt vectors made by golang.org/x/crypto/bcrypt for the agent's gate tests
// (runtime/agent/test/bcrypt.test.ts). Each line of stdin is "<cost> <password as hex>"; each output
// line is a JSON object {"password": "<hex>", "cost": n, "hash": "..."}.
//
//	go run ./runtime/agent/test/tools/bcrypt-vectors.go < input
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	in := bufio.NewScanner(os.Stdin)
	out := json.NewEncoder(os.Stdout)
	for in.Scan() {
		fields := strings.Fields(in.Text())
		if len(fields) == 0 {
			continue
		}
		cost, err := strconv.Atoi(fields[0])
		if err != nil {
			fail(err)
		}
		pw := []byte{}
		if len(fields) > 1 {
			if pw, err = hex.DecodeString(fields[1]); err != nil {
				fail(err)
			}
		}
		h, err := bcrypt.GenerateFromPassword(pw, cost)
		if err != nil {
			fail(err)
		}
		if err := bcrypt.CompareHashAndPassword(h, pw); err != nil {
			fail(err)
		}
		if err := out.Encode(map[string]any{"password": hex.EncodeToString(pw), "cost": cost, "hash": string(h)}); err != nil {
			fail(err)
		}
	}
	if err := in.Err(); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "bcrypt-vectors:", err)
	os.Exit(1)
}
