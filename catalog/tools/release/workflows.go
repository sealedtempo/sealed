package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ActionPin is an action version the workflows may use: the full commit SHA of a release tag. SHAs were
// looked up with `gh api repos/<repo>/commits/<tag>` on 2026-10-28. Each tag is the newest release that
// was at least 14 days old then, except where noted.
type ActionPin struct {
	SHA string
	Tag string
}

// KnownActions lists every action (owner/repo) the workflows use, with its single allowed pin.
var KnownActions = map[string]ActionPin{
	"actions/checkout":             {"3d3c42e5aac5ba805825da76410c181273ba90b1", "v7.0.1"},
	"actions/setup-go":             {"b7ad1dad31e06c5925ef5d2fc7ad053ef454303e", "v7.0.0"},
	"actions/setup-node":           {"949feb2413d6458794dcd2491c4babbbce0c15c1", "v7.1.0"},
	"actions/setup-python":         {"5fda3b95a4ea91299a34e894583c3862153e4b97", "v7.0.0"},
	"actions/upload-artifact":      {"cf430e030ddbb5b0abf93d22962f4752f3646cd9", "v7.0.2"},
	"actions/download-artifact":    {"9000827ccba6bdab643e8b6fd33ac0654aef8333", "v8.0.2"},
	"pnpm/action-setup":            {"ea17c68df8912ef543352723c149a84f56e3d413", "v6.1.0"},
	"foundry-rs/foundry-toolchain": {"908c540300062bd5a7e473851cdb4282204cee09", "v1.9.1"},
	"docker/setup-buildx-action":   {"f87e5991a6d7451dcb8d9637bfbc97413f497069", "v4.4.1"},
	"sigstore/cosign-installer":    {"6f9f17788090df1f26f669e9d70d6ae9567deba6", "v4.1.2"},
	"anchore/sbom-action":          {"66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c", "v0.24.3"},
	"anchore/scan-action":          {"27805bf3b4e84b4a5c980df22ed233c00390a439", "v7.4.2"},
}

// TagReferences are reusable workflows that must be referenced by a vX.Y.Z tag. The SLSA generator fails
// when called by SHA (its provenance names the builder by tag); release.yml checks the tag's commit.
var TagReferences = map[string]string{SLSAGenerator: SLSAGeneratorCommit}

var (
	usesShaRe     = regexp.MustCompile(`^([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(/[A-Za-z0-9_./-]+)?@([0-9a-f]{40})$`)
	dockerUsesRe  = regexp.MustCompile(`^docker://[^@\s]+@sha256:[0-9a-f]{64}$`)
	versionCmtRe  = regexp.MustCompile(`^#\s*(v[0-9][0-9A-Za-z.+-]*)\s*$`)
	untrustedExpr = regexp.MustCompile(`\$\{\{[^}]*(github\.head_ref|github\.event\.(pull_request|issue|comment|review|head_commit|commits|discussion)[^}]*(title|body|ref|label|message|name|email))[^}]*\}\}`)
	secretsExpr   = regexp.MustCompile(`secrets\.([A-Za-z_][A-Za-z0-9_]*)`)
)

// WorkflowProblem is one policy violation.
type WorkflowProblem struct {
	File string
	Line int
	Msg  string
}

func (p WorkflowProblem) String() string { return fmt.Sprintf("%s:%d: %s", p.File, p.Line, p.Msg) }

// CheckWorkflows enforces the workflow policy on every .yml/.yaml file in dir: actions pinned by full
// commit SHA (with a matching version comment) from KnownActions, explicit top-level permissions, no
// pull_request_target, no repository secrets in pull_request workflows, OPS_PRIVATE_KEY only in jobs
// bound to the mainnet environment, and no untrusted event text expanded inside run scripts.
func CheckWorkflows(dir string) ([]WorkflowProblem, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var probs []WorkflowProblem
	for _, e := range entries {
		if e.IsDir() || !(strings.HasSuffix(e.Name(), ".yml") || strings.HasSuffix(e.Name(), ".yaml")) {
			continue
		}
		p := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		probs = append(probs, checkWorkflow(e.Name(), raw)...)
	}
	sort.Slice(probs, func(i, j int) bool {
		if probs[i].File != probs[j].File {
			return probs[i].File < probs[j].File
		}
		return probs[i].Line < probs[j].Line
	})
	return probs, nil
}

func checkWorkflow(name string, raw []byte) []WorkflowProblem {
	var probs []WorkflowProblem
	add := func(line int, format string, a ...any) {
		probs = append(probs, WorkflowProblem{File: name, Line: line, Msg: fmt.Sprintf(format, a...)})
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		add(0, "not valid YAML: %v", err)
		return probs
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		add(0, "not a workflow")
		return probs
	}
	top := doc.Content[0]
	if yamlValue(top, "permissions") == nil {
		add(top.Line, "set top-level permissions (least privilege; jobs add what they need)")
	}
	triggers := map[string]bool{}
	if on := yamlValue(top, "on"); on != nil {
		switch on.Kind {
		case yaml.ScalarNode:
			triggers[on.Value] = true
		case yaml.SequenceNode:
			for _, n := range on.Content {
				triggers[n.Value] = true
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(on.Content); i += 2 {
				triggers[on.Content[i].Value] = true
			}
		}
	}
	if triggers["pull_request_target"] {
		add(top.Line, "pull_request_target runs untrusted code with repository secrets; use pull_request")
	}
	jobs := yamlValue(top, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		add(top.Line, "no jobs")
		return probs
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		jobName, job := jobs.Content[i].Value, jobs.Content[i+1]
		env := yamlValue(job, "environment")
		envName := ""
		if env != nil {
			if env.Kind == yaml.MappingNode {
				if n := yamlValue(env, "name"); n != nil {
					envName = n.Value
				}
			} else {
				envName = env.Value
			}
		}
		walkScalars(job, func(key string, n *yaml.Node) {
			for _, m := range secretsExpr.FindAllStringSubmatch(n.Value, -1) {
				if triggers["pull_request"] && m[1] != "GITHUB_TOKEN" {
					add(n.Line, "job %s: secret %s in a workflow that pull requests trigger", jobName, m[1])
				}
				if m[1] == "OPS_PRIVATE_KEY" && envName != "mainnet" {
					add(n.Line, "job %s: OPS_PRIVATE_KEY is only available to jobs with environment: mainnet", jobName)
				}
			}
			if key == "run" && untrustedExpr.MatchString(n.Value) {
				add(n.Line, "job %s: untrusted event text expanded in a run script; pass it through env instead", jobName)
			}
			if key == "uses" {
				checkUses(n, add)
			}
		})
	}
	return probs
}

func checkUses(n *yaml.Node, add func(int, string, ...any)) {
	v := n.Value
	switch {
	case strings.HasPrefix(v, "./"):
		return
	case strings.HasPrefix(v, "docker://"):
		if !dockerUsesRe.MatchString(v) {
			add(n.Line, "%s: docker actions must be pinned by digest", v)
		}
		return
	}
	if _, ok := TagReferences[v]; ok {
		return
	}
	m := usesShaRe.FindStringSubmatch(v)
	if m == nil {
		add(n.Line, "%s: pin by full commit SHA (owner/repo@<40 hex> # vX.Y.Z)", v)
		return
	}
	pin, ok := KnownActions[m[1]]
	if !ok {
		add(n.Line, "%s: %s is not in the reviewed action list (catalog/tools/release/workflows.go)", v, m[1])
		return
	}
	if m[3] != pin.SHA {
		add(n.Line, "%s: %s must be pinned to %s (%s)", v, m[1], pin.SHA, pin.Tag)
	}
	if c := versionCmtRe.FindStringSubmatch(strings.TrimSpace(n.LineComment)); c == nil || c[1] != pin.Tag {
		add(n.Line, "%s: add the comment `# %s` so reviewers see the version", v, pin.Tag)
	}
}

// walkScalars calls fn for every scalar value below n with the mapping key it belongs to ("" in lists).
func walkScalars(n *yaml.Node, fn func(key string, v *yaml.Node)) {
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if v.Kind == yaml.ScalarNode {
				fn(k.Value, v)
			} else {
				walkScalars(v, fn)
			}
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if c.Kind == yaml.ScalarNode {
				fn("", c)
			} else {
				walkScalars(c, fn)
			}
		}
	}
}
