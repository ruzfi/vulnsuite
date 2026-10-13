// Package cli implements the vulnsuite command line.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/engines"
	"github.com/ruzfi/vulnsuite/pkg/loader"
	"github.com/ruzfi/vulnsuite/pkg/templates"
)

// Exit codes.
const (
	ExitOK    = 0
	ExitFail  = 1
	ExitUsage = 2
)

// Build information, set with -ldflags at release time.
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// usageError marks a command-line mistake (exit 2).
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

// Command is one subcommand.
type Command struct {
	Name    string
	Aliases []string
	Short   string
	Usage   string // one-line synopsis after the command name
	Long    string
	Flags   func(fs *flag.FlagSet)
	Run     func(ctx context.Context, g *Global, fs *flag.FlagSet, args []string) error
}

// Global holds the flags every command accepts.
type Global struct {
	TemplatesDir string
	DockerHost   string
	EngineKind   string
	JSON         bool
	Quiet        bool
	Stdout       io.Writer
	Stderr       io.Writer

	engine engine.Engine
}

func (g *Global) addFlags(fs *flag.FlagSet) {
	// Defaults are the current values so globals parsed before the command
	// name survive being re-registered on the command's flag set.
	fs.StringVar(&g.TemplatesDir, "templates", g.TemplatesDir, "templates directory (default: $VULNSUITE_TEMPLATES, the current repo, or ~/vulnsuite-templates)")
	fs.StringVar(&g.TemplatesDir, "T", g.TemplatesDir, "alias for -templates")
	fs.StringVar(&g.DockerHost, "docker-host", g.DockerHost, "container engine address (default: $DOCKER_HOST or the local socket)")
	fs.StringVar(&g.EngineKind, "engine", g.EngineKind, "container engine client: sdk (the official Moby SDK) or api (built-in, dependency-free); default $VULNSUITE_ENGINE or sdk")
	fs.BoolVar(&g.JSON, "json", g.JSON, "machine-readable JSON output")
	fs.BoolVar(&g.Quiet, "q", g.Quiet, "less output")
}

// Store resolves the templates directory into a loader.Store.
func (g *Global) Store() (*loader.Store, error) {
	dir, err := templates.Resolve(g.TemplatesDir)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("templates directory %s does not exist; run `vulnsuite update-templates` to fetch %s, or pass -templates <dir>", dir, templates.DefaultRepo)
	}
	return loader.New(dir), nil
}

// Engine connects to the container engine (lazily, once).
func (g *Global) Engine(ctx context.Context) (engine.Engine, error) {
	if g.engine != nil {
		return g.engine, nil
	}
	e, err := engines.New(g.EngineKind, g.DockerHost)
	if err != nil {
		return nil, err
	}
	if _, err := e.Ping(ctx); err != nil {
		return nil, err
	}
	g.engine = e
	return e, nil
}

// SetEngine injects an engine (tests, embedding).
func (g *Global) SetEngine(e engine.Engine) { g.engine = e }

// printf writes human progress; with -json it goes to stderr so stdout stays
// machine-readable.
func (g *Global) printf(format string, args ...any) {
	if g.Quiet {
		return
	}
	if g.JSON {
		fmt.Fprintf(g.Stderr, format, args...)
		return
	}
	fmt.Fprintf(g.Stdout, format, args...)
}

func (g *Global) errorf(format string, args ...any) {
	fmt.Fprintf(g.Stderr, format, args...)
}

func (g *Global) emitJSON(v any) error {
	enc := json.NewEncoder(g.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Commands in display order.
func Commands() []*Command {
	return []*Command{
		cmdList(), cmdInfo(), cmdValidate(), cmdBuild(), cmdRun(), cmdStop(), cmdPS(), cmdTargets(),
		cmdImages(), cmdUpdateTemplates(), cmdVersion(),
	}
}

// Main runs the CLI and returns an exit code.
func Main(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return mainWithEngine(ctx, nil, args, stdout, stderr)
}

// mainWithEngine is Main with an injected engine (nil = connect to Docker).
func mainWithEngine(ctx context.Context, eng engine.Engine, args []string, stdout, stderr io.Writer) int {
	g := &Global{Stdout: stdout, Stderr: stderr}
	if eng != nil {
		g.engine = eng
	}
	root := flag.NewFlagSet("vulnsuite", flag.ContinueOnError)
	root.SetOutput(io.Discard)
	g.addFlags(root)
	var showVersion bool
	root.BoolVar(&showVersion, "version", false, "print the version")
	if err := root.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printRootHelp(stdout)
			return ExitOK
		}
		fmt.Fprintln(stderr, "vulnsuite:", err)
		return ExitUsage
	}
	if showVersion {
		fmt.Fprintln(stdout, versionString())
		return ExitOK
	}
	rest := root.Args()
	if len(rest) == 0 {
		printRootHelp(stdout)
		return ExitUsage
	}
	name := rest[0]
	if name == "help" {
		if len(rest) > 1 {
			if c := find(rest[1]); c != nil {
				printCommandHelp(stdout, c)
				return ExitOK
			}
		}
		printRootHelp(stdout)
		return ExitOK
	}
	cmd := find(name)
	if cmd == nil {
		fmt.Fprintf(stderr, "vulnsuite: unknown command %q\n\n", name)
		printRootHelp(stderr)
		return ExitUsage
	}
	fs := flag.NewFlagSet(cmd.Name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	g.addFlags(fs) // globals may also follow the command
	if cmd.Flags != nil {
		cmd.Flags(fs)
	}
	// `run vulnerable -t x`: let the command take leading positionals before flags.
	positional, flagArgs := splitLeadingPositionals(rest[1:])
	if err := fs.Parse(flagArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printCommandHelp(stdout, cmd)
			return ExitOK
		}
		fmt.Fprintf(stderr, "vulnsuite %s: %v\n", cmd.Name, err)
		return ExitUsage
	}
	argv := append(positional, fs.Args()...)
	if err := cmd.Run(ctx, g, fs, argv); err != nil {
		var ue usageError
		if errors.As(err, &ue) {
			fmt.Fprintf(stderr, "vulnsuite %s: %s\n", cmd.Name, ue.msg)
			fmt.Fprintf(stderr, "usage: vulnsuite %s %s\n", cmd.Name, cmd.Usage)
			return ExitUsage
		}
		if errors.Is(err, context.Canceled) {
			return ExitFail
		}
		fmt.Fprintf(stderr, "vulnsuite %s: %v\n", cmd.Name, err)
		return ExitFail
	}
	return ExitOK
}

func splitLeadingPositionals(args []string) (pos, rest []string) {
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			return args[:i], args[i:]
		}
	}
	return args, nil
}

func find(name string) *Command {
	for _, c := range Commands() {
		if c.Name == name {
			return c
		}
		for _, a := range c.Aliases {
			if a == name {
				return c
			}
		}
	}
	return nil
}

func versionString() string {
	s := "vulnsuite " + Version
	if Commit != "" {
		s += " (" + Commit
		if Date != "" {
			s += ", " + Date
		}
		s += ")"
	}
	return s
}

func printRootHelp(w io.Writer) {
	fmt.Fprintln(w, "vulnsuite — build and run reproducible vulnerable targets from templates, in a verified state")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "usage: vulnsuite [-templates DIR] [-json] <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "commands:")
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	for _, c := range Commands() {
		name := c.Name
		if len(c.Aliases) > 0 {
			name += " (" + strings.Join(c.Aliases, ", ") + ")"
		}
		fmt.Fprintf(tw, "  %s\t%s\n", name, c.Short)
	}
	tw.Flush()
	fmt.Fprintln(w)
	fmt.Fprintln(w, "global flags:")
	fmt.Fprintln(w, "  -templates, -T DIR  templates directory (default: $VULNSUITE_TEMPLATES, the current repo, or ~/vulnsuite-templates)")
	fmt.Fprintln(w, "  -docker-host ADDR   container engine (default: $DOCKER_HOST or the local socket)")
	fmt.Fprintln(w, "  -engine sdk|api     Moby SDK client (default) or the built-in API client")
	fmt.Fprintln(w, "  -json               machine-readable output")
	fmt.Fprintln(w, "  -q                  less output")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "run `vulnsuite help <command>` for details.")
}

func printCommandHelp(w io.Writer, c *Command) {
	fmt.Fprintf(w, "usage: vulnsuite %s %s\n\n%s\n", c.Name, c.Usage, c.Short)
	if c.Long != "" {
		fmt.Fprintln(w)
		fmt.Fprintln(w, strings.TrimSpace(c.Long))
	}
	fs := flag.NewFlagSet(c.Name, flag.ContinueOnError)
	if c.Flags != nil {
		c.Flags(fs)
	}
	var lines []string
	fs.VisitAll(func(f *flag.Flag) {
		def := ""
		if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" {
			def = " (default " + f.DefValue + ")"
		}
		lines = append(lines, fmt.Sprintf("  -%s\t%s%s", f.Name, f.Usage, def))
	})
	if len(lines) > 0 {
		sort.Strings(lines)
		fmt.Fprintln(w)
		fmt.Fprintln(w, "flags:")
		tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
		for _, l := range lines {
			fmt.Fprintln(tw, l)
		}
		tw.Flush()
	}
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
