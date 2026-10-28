package app

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/sealed-dev/sealed/cli/internal/deploy"
	"github.com/sealed-dev/sealed/cli/internal/secrets"
	"github.com/sealed-dev/sealed/cli/internal/token"
	"github.com/sealed-dev/sealed/runtime/composer"
)

const secretsUsage = `Usage:
  sealed secrets set <app> <NAME> [--generate [--kind <generator>] | --value-file <file> | --stdin] [--rotate]
  sealed secrets set gate [--generate | --value-file <file> | --stdin] [--rotate]
  sealed secrets set --config stack.yaml --missing
  sealed secrets list [--config stack.yaml | --apps a,b]
  sealed secrets rm <app> <NAME> | gate [--yes]

Secrets live in your project's Secret Manager as sealed-<app>-<NAME>; the key broker may read only those.
The gate password is stored as its bcrypt hash in sealed-gate-password. Values are never printed or read back.
A secret declared with same_as is stored once, under the app it refers to.
`

type secretsFlags struct {
	c                                commonFlags
	project, connection, config      string
	catalog, apps, location, kind    string
	valueFile                        string
	stdin, generate, rotate, missing bool
	yes                              bool
}

func (f *secretsFlags) register(fs interface {
	StringVar(*string, string, string, string)
	BoolVar(*bool, string, bool, string)
}) {
	fs.StringVar(&f.project, "project", "", "Google Cloud project (default: from --connection or --config)")
	fs.StringVar(&f.connection, "connection", "", "sct_ connection token from sealed bootstrap")
	fs.StringVar(&f.config, "config", "", "stack.yaml: its project and apps")
	fs.StringVar(&f.catalog, "catalog", "", "local catalog/apps directory with the manifests (default: ./catalog/apps when present, else the release bundles of --config)")
	fs.StringVar(&f.apps, "apps", "", "comma-separated app ids (with --catalog)")
	fs.StringVar(&f.location, "location", "", "replicate new secrets only to this location (default automatic)")
	fs.StringVar(&f.kind, "kind", "", "generator for --generate (default the manifest's)")
	fs.StringVar(&f.valueFile, "value-file", "", "read the value from this file (one trailing newline is dropped)")
	fs.BoolVar(&f.stdin, "stdin", false, "read the value from standard input")
	fs.BoolVar(&f.generate, "generate", false, "generate the value")
	fs.BoolVar(&f.rotate, "rotate", false, "add a new version to an existing secret")
	fs.BoolVar(&f.missing, "missing", false, "set every required secret of the stack that has no value yet")
	fs.BoolVar(&f.yes, "yes", false, "do not ask for confirmation")
}

func runSecrets(ctx context.Context, args []string, e *Env) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(e.Stderr, secretsUsage)
		if len(args) == 0 {
			return usagef("sealed secrets needs set, list or rm")
		}
		return nil
	}
	sub := args[0]
	fs := newFlags("sealed secrets "+sub, e)
	f := &secretsFlags{}
	f.c.register(fs)
	f.register(fs)
	pos, err := parse(fs, args[1:])
	if err != nil {
		return err
	}
	switch sub {
	case "set":
		return secretsSet(ctx, e, f, pos)
	case "list", "ls":
		return secretsList(ctx, e, f, pos)
	case "rm", "delete":
		return secretsRm(ctx, e, f, pos)
	}
	return usagef("unknown secrets command %q\n\n%s", sub, secretsUsage)
}

// project resolves the project from the flags.
func (f *secretsFlags) resolveProject(stack *deploy.StackFile) (string, error) {
	if f.project != "" {
		return f.project, nil
	}
	if f.connection != "" {
		c, err := token.Decode(f.connection)
		if err != nil {
			return "", err
		}
		return c.Project, nil
	}
	if stack != nil {
		return stack.Project, nil
	}
	return "", usagef("name the project with --project, --connection or --config")
}

func (f *secretsFlags) stack() (*deploy.StackFile, error) {
	if f.config == "" {
		return nil, nil
	}
	return deploy.LoadStackFile(f.config)
}

// manifests loads the secrets of the stack's apps: from a local catalog, or from the release bundles the stack
// file names (fetched by onchain bundleHash).
func (f *secretsFlags) manifests(ctx context.Context, e *Env, stack *deploy.StackFile, only []string) ([]*secrets.App, error) {
	ids := only
	if len(ids) == 0 && f.apps != "" {
		for _, a := range strings.Split(f.apps, ",") {
			if a = strings.TrimSpace(a); a != "" {
				ids = append(ids, a)
			}
		}
	}
	if len(ids) == 0 && stack != nil {
		for _, a := range stack.Apps {
			ids = append(ids, a.ID)
		}
	}
	if len(ids) == 0 {
		return nil, usagef("name the apps with --config or --apps")
	}
	catalog := f.catalog
	if catalog == "" && stack == nil {
		if st, err := os.Stat(filepath.Join("catalog", "apps")); err == nil && st.IsDir() {
			catalog = filepath.Join("catalog", "apps")
		}
	}
	if catalog != "" {
		return secrets.LoadCatalog(catalog, ids)
	}
	if stack == nil {
		return nil, usagef("no manifests: pass --catalog <catalog/apps> or --config stack.yaml")
	}
	s, err := f.c.settings(e)
	if err != nil {
		return nil, err
	}
	reader, err := e.chain(ctx, s)
	if err != nil {
		return nil, err
	}
	fetcher := f.c.fetcher(e, s)
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var out []*secrets.App
	for _, a := range stack.Apps {
		if !want[a.ID] {
			continue
		}
		rel, err := deploy.ResolveRelease(ctx, reader, a)
		if err != nil {
			return nil, err
		}
		b, err := fetcher.Load(ctx, rel)
		if err != nil {
			return nil, err
		}
		app, err := secrets.ParseManifest(b.Files[composer.ManifestFile])
		if err != nil {
			return nil, err
		}
		out = append(out, app)
	}
	return out, nil
}

func (f *secretsFlags) manager(e *Env, project string) (*secrets.Manager, error) {
	ts, err := e.tokens("")
	if err != nil {
		return nil, err
	}
	return &secrets.Manager{Store: e.secretStore(project, ts), Location: f.location}, nil
}

// readValue gets a value from --value-file, --stdin or a no-echo prompt.
func (f *secretsFlags) readValue(e *Env, label string) (string, error) {
	switch {
	case f.valueFile != "" && f.stdin:
		return "", usagef("use --value-file or --stdin, not both")
	case f.valueFile != "":
		b, err := os.ReadFile(f.valueFile)
		if err != nil {
			return "", err
		}
		return trimNewline(string(b)), nil
	case f.stdin:
		b, err := io.ReadAll(io.LimitReader(e.Stdin, 64<<10+1))
		if err != nil {
			return "", err
		}
		return trimNewline(string(b)), nil
	case e.Interactive && e.ReadSecret != nil:
		return e.ReadSecret(label + ": ")
	}
	return "", usagef("no value: pass --generate, --value-file <file> or --stdin")
}

func trimNewline(s string) string {
	s = strings.TrimSuffix(s, "\n")
	return strings.TrimSuffix(s, "\r")
}

func secretsSet(ctx context.Context, e *Env, f *secretsFlags, pos []string) error {
	stack, err := f.stack()
	if err != nil {
		return err
	}
	project, err := f.resolveProject(stack)
	if err != nil {
		return err
	}
	if f.missing {
		if len(pos) > 0 {
			return usagef("--missing takes no app or name")
		}
		return secretsFillMissing(ctx, e, f, stack, project)
	}
	if len(pos) == 1 && pos[0] == secrets.GateApp {
		return secretsSetGate(ctx, e, f, project)
	}
	if len(pos) != 2 {
		return usagef("usage: sealed secrets set <app> <NAME> | gate | --missing")
	}
	app, name := pos[0], pos[1]
	apps, err := f.manifests(ctx, e, stack, []string{app})
	if err != nil {
		return err
	}
	if len(apps) != 1 {
		return fmt.Errorf("app %s is not in the stack", app)
	}
	decl, ok := apps[0].Secret(name)
	if !ok {
		var names []string
		for _, s := range apps[0].Secrets {
			names = append(names, s.Name)
		}
		return fmt.Errorf("%s does not declare a secret %s (it declares %s)", app, name, strings.Join(names, ", "))
	}
	if decl.SameAs != "" {
		ref := strings.SplitN(decl.SameAs, "/", 2)
		return fmt.Errorf("%s/%s is the same as %s: set that one (sealed secrets set %s %s); the key broker hands it to %s too", app, name, decl.SameAs, ref[0], ref[1], app)
	}
	var value string
	if f.generate {
		kind := f.kind
		if kind == "" {
			kind = decl.Generate
		}
		if value, err = secrets.Generate(kind, nil); err != nil {
			return fmt.Errorf("%s/%s: %w", app, name, err)
		}
	} else if value, err = f.readValue(e, app+"/"+name); err != nil {
		return err
	}
	m, err := f.manager(e, project)
	if err != nil {
		return err
	}
	stored := secrets.StoredName(app, name)
	created, err := m.Put(ctx, stored, secrets.Labels(app, name), []byte(value), f.rotate)
	if err != nil {
		return err
	}
	verb := "added a new version to"
	if created {
		verb = "created"
	}
	e.printf("%s %s in project %s\n", verb, stored, project)
	return nil
}

func secretsSetGate(ctx context.Context, e *Env, f *secretsFlags, project string) error {
	var pw string
	var err error
	if f.generate {
		if pw, err = secrets.Generate("password", nil); err != nil {
			return err
		}
	} else if pw, err = f.readValue(e, "Gate password (at least 12 characters)"); err != nil {
		return err
	}
	hash, err := secrets.GateHash(pw)
	if err != nil {
		return err
	}
	m, err := f.manager(e, project)
	if err != nil {
		return err
	}
	if _, err := m.Put(ctx, secrets.GateSecret, secrets.Labels(secrets.GateApp, ""), []byte(hash), f.rotate); err != nil {
		return err
	}
	e.printf("stored the bcrypt hash of the gate password in %s (project %s)\n", secrets.GateSecret, project)
	if f.generate {
		e.printf("\nGate password (user sealed). It is shown only now:\n\n  %s\n\n", pw)
	}
	return nil
}

func secretsFillMissing(ctx context.Context, e *Env, f *secretsFlags, stack *deploy.StackFile, project string) error {
	apps, err := f.manifests(ctx, e, stack, nil)
	if err != nil {
		return err
	}
	plan, err := secrets.NewPlan(apps)
	if err != nil {
		return err
	}
	m, err := f.manager(e, project)
	if err != nil {
		return err
	}
	var ask secrets.Asker
	if e.Interactive && e.ReadSecret != nil {
		ask = func(stored, desc string) (string, bool, error) {
			if desc != "" {
				e.errorf("%s: %s\n", stored, oneLine(desc))
			}
			v, err := e.ReadSecret(stored + ": ")
			return v, v != "", err
		}
	}
	res, err := m.FillMissing(ctx, plan, ask, true)
	if res != nil {
		for _, n := range res.Generated {
			e.printf("generated %s\n", n)
		}
		for _, n := range res.Supplied {
			e.printf("stored    %s\n", n)
		}
		for _, n := range res.Skipped {
			e.printf("optional  %s (not set)\n", n)
		}
		if res.GatePassword != "" {
			e.printf("\nGate password (user sealed). It is shown only now:\n\n  %s\n\n", res.GatePassword)
		}
	}
	if err != nil {
		return err
	}
	if len(res.Missing) > 0 {
		return &exitError{code: ExitFailed, msg: "still missing (set each with sealed secrets set <app> <NAME> --value-file <file>):\n  " + strings.Join(res.Missing, "\n  ")}
	}
	e.printf("every required secret of the stack has a value\n")
	return nil
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func secretsList(ctx context.Context, e *Env, f *secretsFlags, pos []string) error {
	if len(pos) > 0 {
		return usagef("sealed secrets list takes no positional arguments")
	}
	stack, err := f.stack()
	if err != nil {
		return err
	}
	project, err := f.resolveProject(stack)
	if err != nil {
		return err
	}
	m, err := f.manager(e, project)
	if err != nil {
		return err
	}
	if stack == nil && f.apps == "" {
		list, err := m.Store.List(ctx, secrets.Prefix)
		if err != nil {
			return err
		}
		if f.c.json {
			return writeJSON(e.Stdout, list)
		}
		tw := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "SECRET\tAPP\tNAME\tCREATED")
		for _, s := range list {
			app, name, _ := secrets.ParseStoredName(s.Name)
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", s.Name, app, name, s.CreateTime)
		}
		return tw.Flush()
	}
	apps, err := f.manifests(ctx, e, stack, nil)
	if err != nil {
		return err
	}
	plan, err := secrets.NewPlan(apps)
	if err != nil {
		return err
	}
	st, gate, err := m.Inspect(ctx, plan)
	if err != nil {
		return err
	}
	type row struct {
		App, Name, Stored, Status, Generator string
	}
	var rows []row
	missing := 0
	for _, s := range st {
		status := "set"
		switch {
		case s.SameAs != "" && s.Present:
			status = "same as " + s.SameAs + " (set)"
		case s.SameAs != "":
			status = "same as " + s.SameAs + " (missing)"
			if !s.Optional {
				missing++
			}
		case !s.Present && s.Optional:
			status = "optional, not set"
		case !s.Present:
			status = "missing"
			missing++
		}
		rows = append(rows, row{s.App, s.Name, s.Stored, status, s.Generate})
	}
	gateStatus := "set"
	if !gate {
		gateStatus = "missing"
		missing++
	}
	rows = append(rows, row{"gate", "GATE_PASSWORD_BCRYPT", secrets.GateSecret, gateStatus, "password"})
	if f.c.json {
		return writeJSON(e.Stdout, map[string]any{"project": project, "missing": missing, "secrets": rows})
	}
	tw := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "APP\tNAME\tSECRET\tSTATUS\tGENERATOR")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.App, r.Name, r.Stored, r.Status, r.Generator)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if missing > 0 {
		e.printf("\n%d required secret(s) missing: sealed secrets set --config <stack file> --missing\n", missing)
	}
	return nil
}

func secretsRm(ctx context.Context, e *Env, f *secretsFlags, pos []string) error {
	var stored string
	switch {
	case len(pos) == 1 && pos[0] == secrets.GateApp:
		stored = secrets.GateSecret
	case len(pos) == 2:
		stored = secrets.StoredName(pos[0], pos[1])
		if _, _, ok := secrets.ParseStoredName(stored); !ok {
			return usagef("%s/%s is not an app secret name", pos[0], pos[1])
		}
	default:
		return usagef("usage: sealed secrets rm <app> <NAME> | gate")
	}
	stack, err := f.stack()
	if err != nil {
		return err
	}
	project, err := f.resolveProject(stack)
	if err != nil {
		return err
	}
	if !f.yes {
		if !e.Interactive {
			return usagef("not a terminal: pass --yes to delete %s", stored)
		}
		e.errorf("Delete %s and all its versions from project %s? Apps that need it will not start. [y/N] ", stored, project)
		line, _ := bufio.NewReader(e.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			return &exitError{code: ExitFailed, msg: "not deleted"}
		}
	}
	m, err := f.manager(e, project)
	if err != nil {
		return err
	}
	if err := m.Store.Delete(ctx, stored); err != nil {
		return err
	}
	e.printf("deleted %s from project %s\n", stored, project)
	return nil
}
