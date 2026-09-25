// Command signet is a machine-identity attest client for Portcullis, the
// household secrets broker.
//
// signet holds a P-256 private key in a PKCS8 PEM file and speaks the
// /v1/attest attestation protocol: it signs a broker challenge with that key
// and exchanges the proof for a short-lived bearer token.
//
// Usage:
//
//	signet enrol   [flags]
//	signet sign    [flags] <message>
//	signet auth    [flags] <broker-url>
//	signet verify  [flags] --broker <url> [--credential <name>]
//	signet headers [flags] --broker <url> --credential <name> [--header <name>] [--format bearer|raw] [--bare]
//	signet vend-to-file [flags] --broker <url> [--field <name>] [--mode <octal>] [--print-shape] <name> <dest>
//	signet exec    [flags] --broker <url> --credential <name> --env-var <NAME> [--field <name>] -- <command> [args...]
//	signet version
//	signet doctor  [flags]
//
// Flags (enrol, sign, auth, verify, headers, vend-to-file, exec, doctor):
//
//	--identity  <name>   key name (default: $SIGNET_IDENTITY, else consumer)
//	--key       <path>   explicit key file path (default: $XDG_CONFIG_HOME/portcullis/<identity>.key)
//
// SIGNET_IDENTITY sets --identity's default when the flag is absent; a passed
// flag always wins.
//
// --identity names the local key, the way an SSH key filename picks one key
// of several, so one machine can hold more than one identity — each maps to
// its own key file under $XDG_CONFIG_HOME/portcullis. It is local-only and
// never sent to the broker, which resolves the identity from the presented
// public key (resolve-by-key). --key overrides the computed path directly,
// for a caller that wants to name the file itself rather than by identity.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/radar-hooves/signet/internal/attest"
	"github.com/radar-hooves/signet/internal/signer"
)

// version is overwritten at link time by -ldflags "-X main.version=<value>".
var version = "dev"

func main() {
	// 'verify' and 'headers' are handled here rather than in run() because they
	// need typed exit codes (2–6) that cannot be expressed as errors and still
	// give os.Exit(1).
	if len(os.Args) > 1 && os.Args[1] == "verify" {
		os.Exit(runVerify(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "headers" {
		os.Exit(runHeaders(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "vend-to-file" {
		os.Exit(runVendToFile(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "exec" {
		os.Exit(runExec(os.Args[2:]))
	}
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// runVerify parses verify's flags and calls attest.Verify, returning the typed
// exit code. It is separate from run() so typed exits never conflict with
// run()'s single error/exit-1 contract.
func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	identity, key := signerFlags(fs)
	broker := fs.String("broker", "", "broker URL (required)")
	cred := fs.String("credential", "", "credential name to probe (optional)")
	help, err := parseArgs(fs, args)
	if help {
		return 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if *broker == "" {
		fmt.Fprintln(os.Stderr, "error: signet verify: --broker is required")
		return 1
	}
	s, err := selectSigner(*identity, *key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	// attest.Verify reports every failure on its own output; do not repeat the
	// error on stderr here, or transport failures would print twice.
	code, _ := attest.Verify(s, *broker, *cred)
	return code
}

// runHeaders parses headers' flags and calls attest.Headers, returning the
// typed exit code. It is separate from run() so typed exits never conflict
// with run()'s single error/exit-1 contract.
func runHeaders(args []string) int {
	fs := flag.NewFlagSet("headers", flag.ContinueOnError)
	fs.Usage = headersUsage
	identity, key := signerFlags(fs)
	broker := fs.String("broker", "", "broker URL (required)")
	cred := fs.String("credential", "", "credential name to vend (required)")
	header := fs.String("header", "Authorization", `HTTP header name to key the JSON object by (ignored, and refused, with --bare)`)
	format := fs.String("format", "bearer", `value shape: "bearer" (emits "Bearer <value>") or "raw" (emits <value> alone)`)
	bare := fs.Bool("bare", false, `print the value alone instead of a compact-JSON object (for "curl -H" interpolation)`)
	help, err := parseArgs(fs, args)
	if help {
		return 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if *broker == "" {
		fmt.Fprintln(os.Stderr, "error: signet headers: --broker is required")
		return 1
	}
	if *cred == "" {
		fmt.Fprintln(os.Stderr, "error: signet headers: --credential is required")
		return 1
	}
	if strings.TrimSpace(*header) == "" {
		fmt.Fprintln(os.Stderr, "error: signet headers: --header must not be empty")
		return 1
	}
	if *format != "bearer" && *format != "raw" {
		fmt.Fprintf(os.Stderr, "error: signet headers: --format must be \"bearer\" or \"raw\", got %q\n", *format)
		return 1
	}
	// --bare prints no header name, so an explicitly-set --header could not be
	// honoured. Refuse rather than ignore it: silently accepting a flag that
	// does nothing is the failure this command already cost two sessions to.
	// fs.Visit reports only flags actually set, so the "Authorization" default
	// does not trip this.
	if *bare && isFlagSet(fs, "header") {
		fmt.Fprintf(os.Stderr, "error: signet headers: --header cannot be combined with --bare (--bare prints the value alone, with no header name); drop --header, or drop --bare to get %s\n", jsonShapeExample(*header, *format))
		return 1
	}
	s, err := selectSigner(*identity, *key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	// attest.Headers reports every failure on stderr; do not repeat the error
	// here, or failures would print twice.
	code, _ := attest.Headers(s, *broker, *cred, *header, *format, *bare)
	return code
}

// jsonShapeExample renders the JSON shape the given --header/--format pair
// would produce, for use in a diagnostic. It is derived from the actual flag
// values rather than hardcoded, because the shape depends on --format: a
// hardcoded {"<name>":"<value>"} is wrong under the default --format bearer,
// which yields {"<name>":"Bearer <value>"}. Naming the wrong shape in an error
// about output shapes is the defect this command was fixed for (#5).
func jsonShapeExample(headerName, format string) string {
	if format == "bearer" {
		return fmt.Sprintf("{%q:\"Bearer <value>\"}", headerName)
	}
	return fmt.Sprintf("{%q:\"<value>\"}", headerName)
}

// isFlagSet reports whether name was explicitly passed on the command line,
// as opposed to holding its default. flag exposes no direct query for this;
// Visit walks only the flags actually set.
func isFlagSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// runVendToFile parses vend-to-file's flags and calls attest.VendToFile,
// returning the typed exit code. It is separate from run() so typed exits
// never conflict with run()'s single error/exit-1 contract.
func runVendToFile(args []string) int {
	fs := flag.NewFlagSet("vend-to-file", flag.ContinueOnError)
	identity, key := signerFlags(fs)
	broker := fs.String("broker", "", "broker URL (required)")
	field := fs.String("field", "", "static-material field to write (required when the credential has more than one static field; ignored for session material, which always writes access_token)")
	modeFlag := fs.String("mode", "0600", "file mode for the written destination, octal (e.g. 0600)")
	printShape := fs.Bool("print-shape", false, "print the credential's kind and field names, write no file, and exit")
	help, err := parseArgs(fs, args)
	if help {
		return 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if *broker == "" {
		fmt.Fprintln(os.Stderr, "error: signet vend-to-file: --broker is required")
		return 1
	}
	if fs.NArg() < 2 {
		fmt.Fprintln(os.Stderr, "error: signet vend-to-file: a credential name and destination path argument are required (signet vend-to-file [flags] <name> <dest>)")
		return 1
	}
	mode, modeErr := parseFileMode(*modeFlag)
	if modeErr != nil {
		fmt.Fprintf(os.Stderr, "error: signet vend-to-file: --mode: %v\n", modeErr)
		return 1
	}
	s, err := selectSigner(*identity, *key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	// attest.VendToFile reports every failure on stderr; do not repeat the
	// error here, or failures would print twice.
	code, _ := attest.VendToFile(s, *broker, fs.Arg(0), fs.Arg(1), *field, mode, *printShape)
	return code
}

// parseFileMode parses an octal file-mode flag value (e.g. "0600" or "600"),
// bounded to the 12 permission/sticky/setuid/setgid bits POSIX defines
// (0-07777). Without this bound an oversized value like "20000000000" would
// still parse (into an os.FileMode with high bits os.Chmod silently strips),
// producing a confusing inaccessible "----------" dest instead of a clear
// error at the flag-parsing boundary.
func parseFileMode(s string) (os.FileMode, error) {
	v, err := strconv.ParseUint(s, 8, 12)
	if err != nil {
		if errors.Is(err, strconv.ErrRange) {
			return 0, fmt.Errorf("mode %q out of range (must be 0-07777)", s)
		}
		return 0, fmt.Errorf("invalid octal mode %q: %w", s, err)
	}
	return os.FileMode(v), nil
}

// parseArgs parses args with fs, treating -h/--help as success: the flag
// package has already printed the flag list to stderr, so the caller should
// simply exit 0 rather than wrapping flag.ErrHelp in an "error:" line.
func parseArgs(fs *flag.FlagSet, args []string) (help bool, err error) {
	err = fs.Parse(args)
	if errors.Is(err, flag.ErrHelp) {
		return true, nil
	}
	return false, err
}

// envOr returns the named environment variable's value, or fallback if it is
// unset or empty. An explicitly-exported empty value is treated the same as
// unset, so a host's env block can be present-but-blank without it
// overriding a flag's built-in default with an empty string.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// signerFlags registers the identity/key selection flags shared by every
// signing subcommand on fs and returns pointers to their parsed values.
//
// --identity defaults to SIGNET_IDENTITY when the flag is not passed, so a
// host can name its identity ONCE in its own environment (a fleet-declared
// Claude Code `env` block, not a shell profile) and have every invocation
// honour it — the flag always wins when passed.
func signerFlags(fs *flag.FlagSet) (identity, key *string) {
	identity = fs.String("identity", envOr("SIGNET_IDENTITY", ""), "key name (default: $SIGNET_IDENTITY, else consumer)")
	key = fs.String("key", "", "path to the P-256 key file (default: $XDG_CONFIG_HOME/portcullis/<identity>.key)")
	return
}

// selectSigner builds the software signer for the given identity/key
// selection: an explicit --key wins outright, else the path is computed from
// --identity.
func selectSigner(identity, key string) (signer.Signer, error) {
	return signer.New(key, identity)
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		printHelp()
		return nil
	}

	switch args[0] {
	case "enrol":
		fs := flag.NewFlagSet("enrol", flag.ContinueOnError)
		identity, key := signerFlags(fs)
		help, err := parseArgs(fs, args[1:])
		if help {
			return nil
		}
		if err != nil {
			return err
		}
		s, err := selectSigner(*identity, *key)
		if err != nil {
			return err
		}
		spki, err := s.Enrol()
		if err != nil {
			return err
		}
		fmt.Println(spki)
		return nil

	case "sign":
		fs := flag.NewFlagSet("sign", flag.ContinueOnError)
		identity, key := signerFlags(fs)
		help, err := parseArgs(fs, args[1:])
		if help {
			return nil
		}
		if err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return fmt.Errorf("signet sign: a message argument is required (signet sign [flags] <message>)")
		}
		s, err := selectSigner(*identity, *key)
		if err != nil {
			return err
		}
		sig, err := s.Sign(fs.Arg(0))
		if err != nil {
			return err
		}
		fmt.Println(sig)
		return nil

	case "auth":
		fs := flag.NewFlagSet("auth", flag.ContinueOnError)
		identity, key := signerFlags(fs)
		help, err := parseArgs(fs, args[1:])
		if help {
			return nil
		}
		if err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return fmt.Errorf("signet auth: a broker URL argument is required (signet auth [flags] <broker-url>)")
		}
		s, err := selectSigner(*identity, *key)
		if err != nil {
			return err
		}
		return attest.Auth(s, fs.Arg(0))

	case "version":
		// runtime.Version() already carries the "go" prefix (e.g. go1.25.10).
		fmt.Printf("signet %s %s/%s (%s)\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return nil

	case "doctor":
		fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
		identity, key := signerFlags(fs)
		help, err := parseArgs(fs, args[1:])
		if help {
			return nil
		}
		if err != nil {
			return err
		}
		return cmdDoctor(*identity, *key)

	case "verify":
		// Reached only if someone calls run("verify", ...) directly (e.g. in tests
		// that go through run()). In practice main() short-circuits verify before
		// run() is called, so this branch exists only for completeness.
		return fmt.Errorf("use 'signet verify' directly; typed exit codes require os.Exit")

	case "headers":
		// Reached only if someone calls run("headers", ...) directly (e.g. in
		// tests that go through run()). In practice main() short-circuits headers
		// before run() is called, so this branch exists only for completeness.
		return fmt.Errorf("use 'signet headers' directly; typed exit codes require os.Exit")

	case "vend-to-file":
		// Reached only if someone calls run("vend-to-file", ...) directly (e.g.
		// in tests that go through run()). In practice main() short-circuits
		// vend-to-file before run() is called, so this branch exists only for
		// completeness.
		return fmt.Errorf("use 'signet vend-to-file' directly; typed exit codes require os.Exit")

	case "exec":
		// Reached only if someone calls run("exec", ...) directly (e.g. in
		// tests that go through run()). In practice main() short-circuits
		// exec before run() is called, so this branch exists only for
		// completeness.
		return fmt.Errorf("use 'signet exec' directly; typed exit codes require os.Exit")

	default:
		return fmt.Errorf("unknown subcommand %q\n\n%s", args[0], helpText())
	}
}

// printHelp writes the help block to stdout.
func printHelp() {
	fmt.Print(helpText())
}

// headersHelpBody returns the `headers` flag, output-shape, and exit-code
// reference. It is the ONE copy: helpText embeds it for `signet --help`, and
// runHeaders installs it as the FlagSet's Usage for `signet headers --help`.
// Two hand-maintained copies would drift, and a drifting help text is the
// defect this command was fixed for in the first place (#5).
func headersHelpBody() string {
	return `Headers flags:
  --broker     <url>    broker URL (required)
  --credential <name>   credential name to vend (required)
  --header     <name>   HTTP header name to key the JSON object by (default: Authorization;
                          cannot be combined with --bare, which prints no name)
  --format     bearer | raw   value shape: "Bearer <value>" or <value> alone (default: bearer)
  --bare                print the value alone, not a compact-JSON object

Headers output shapes (--format shapes the value, --bare shapes the framing):
  (default)             {"Authorization":"Bearer s3cr3t"}
  --format raw          {"Authorization":"s3cr3t"}
  --bare                Bearer s3cr3t
  --bare --format raw   s3cr3t

  The JSON shapes are the Claude Code .mcp.json headersHelper contract and are
  the default. Use --bare for shell interpolation — a JSON-wrapped value inside
  curl -H "Authorization: Bearer $v" builds a malformed header, which a broker
  rejects as a 401 that looks exactly like a stale credential:
    v=$(signet headers --broker <url> --credential <name> --bare --format raw)
    curl -H "Authorization: Bearer $v" <url>

Headers exit codes:
  0  success — header line printed to stdout
  2  key missing — no key enrolled for this identity
  3  attestation rejected — broker refused the attestation
  4  credential out of scope — identity exists but credential is not in its scope
  5  credential not found — credential name absent from the catalogue
  6  unusable material — credential resolves to no single value (not one
     static field, and not a session carrying an access_token)

`
}

// headersUsage is the FlagSet Usage for `signet headers`. flag prints Usage on
// -h/--help and then returns ErrHelp, so without this the subcommand's help is
// only flag's own bare list of flags — never the output shapes a caller needs
// to see BEFORE interpolating stdout into a shell command.
func headersUsage() {
	fmt.Fprint(os.Stderr, `signet headers — attest, vend a credential, and print it as one HTTP header

Usage:
  signet headers --broker <url> --credential <name> [--header <name>] [--format bearer|raw] [--bare]

`+headersHelpBody()+`Key selection flags (--identity, --key): signet --help
`)
}

// helpText returns the structured help block listing all subcommands.
func helpText() string {
	return `signet — machine-identity attest client for Portcullis

Usage:
  signet <subcommand> [flags]

Subcommands:
  enrol         Generate (or recover) the key and print the SPKI public key
  sign          Sign a message with the key and print the base64 signature
  auth          Attest to a broker and print the Authorization header (JSON)
  verify        Consumer pre-flight: attest and optionally probe a credential vend
  headers       Attest, vend a credential, and print one HTTP header (compact JSON, or --bare)
  vend-to-file  Attest, vend a credential, and write one field's value to a file
  exec          Attest, vend a credential, set it as an env var, and exec a command
  version       Print the signet version, platform, and Go runtime
  doctor        Probe the key file and report its availability

Flags (enrol, sign, auth, verify, headers, vend-to-file, exec, doctor):
  --identity   <name>   key name (default: $SIGNET_IDENTITY, else consumer)
  --key        <path>   explicit key file path (default: $XDG_CONFIG_HOME/portcullis/<identity>.key)

SIGNET_IDENTITY sets --identity's default when the flag is absent; a passed
flag always wins.

Verify flags:
  --broker     <url>    broker URL (required)
  --credential <name>   credential name to probe vend scope (optional)

Verify exit codes:
  0  success — attestation accepted; credential resolvable (if --credential given)
  2  key missing — no key enrolled for this identity
  3  attestation rejected — broker refused the attestation
  4  credential out of scope — identity exists but credential is not in its scope
  5  credential not found — credential name absent from the catalogue

` + headersHelpBody() + `
Vend-to-file flags:
  signet vend-to-file [flags] <name> <dest>
  --broker      <url>    broker URL (required)
  --field       <name>   static field to write (required when the credential
                          has more than one static field; ignored for session
                          material, which always writes access_token)
  --mode        <octal>  file mode for <dest> (default: 0600)
  --print-shape          print the credential's kind and field names, write no
                          file, and exit

Vend-to-file exit codes:
  0  success — <dest> written atomically at the chosen mode (or, with
     --print-shape, the kind and field names printed instead)
  2  key missing — no key enrolled for this identity
  3  attestation rejected — broker refused the attestation
  4  credential out of scope — identity exists but credential is not in its scope
  5  credential not found — credential name absent from the catalogue
  6  unusable material — credential cannot be resolved to a single field's value

` + execHelpBody()
}
