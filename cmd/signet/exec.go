// exec.go: 'signet exec' — the cmd-layer flag parsing and dispatch for
// attest.Exec. Mirrors runHeaders/runVendToFile's shape; the one addition is
// splitting os.Args on the "--" terminator that separates signet's own
// flags from the child command's, since flag.FlagSet consumes "--" silently
// (it stops parsing there) and offers no way to tell afterwards whether it
// was present at all.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/radar-hooves/signet/internal/attest"
)

// runExec parses exec's flags and calls attest.Exec, returning the typed
// exit code. It is separate from run() so typed exits never conflict with
// run()'s single error/exit-1 contract.
//
// On success attest.Exec never returns — the process image is replaced by
// the child — so a return from runExec, of any kind, is always a failure.
func runExec(args []string) int {
	// Split args on the first literal "--" ourselves, before fs.Parse ever
	// sees them: flag.FlagSet treats "--" as the flag terminator and simply
	// drops it, so by the time Parse returns there is no way to distinguish
	// "the user wrote --" from "the user wrote nothing at all". Everything
	// after "--" is the child's argv and must never be interpreted as a
	// signet flag.
	sepIdx := -1
	for i, a := range args {
		if a == "--" {
			sepIdx = i
			break
		}
	}
	flagArgs := args
	if sepIdx >= 0 {
		flagArgs = args[:sepIdx]
	}

	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	fs.Usage = execUsage
	backend, slot, identity, agentSock := signerFlags(fs)
	broker := fs.String("broker", "", "broker URL (required)")
	cred := fs.String("credential", "", "credential name to vend (required)")
	envVar := fs.String("env-var", "", "environment variable name to set on the child process (required)")
	field := fs.String("field", "", "static-material field to set (required when the credential has more than one static field; ignored for session material, which always sets access_token)")

	// -h/--help works even without a "--", so `signet exec --help` behaves
	// like every other subcommand.
	help, err := parseArgs(fs, flagArgs)
	if help {
		return 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if sepIdx < 0 {
		fmt.Fprintln(os.Stderr, "error: signet exec: missing -- separator (usage: signet exec [flags] -- <command> [args...])")
		return 1
	}
	childArgv := args[sepIdx+1:]
	if len(childArgv) == 0 {
		fmt.Fprintln(os.Stderr, "error: signet exec: a command is required after -- (usage: signet exec [flags] -- <command> [args...])")
		return 1
	}
	if *broker == "" {
		fmt.Fprintln(os.Stderr, "error: signet exec: --broker is required")
		return 1
	}
	if *cred == "" {
		fmt.Fprintln(os.Stderr, "error: signet exec: --credential is required")
		return 1
	}
	if *envVar == "" {
		fmt.Fprintln(os.Stderr, "error: signet exec: --env-var is required")
		return 1
	}
	s, err := selectSigner(*backend, *slot, *identity, *agentSock)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	// attest.Exec reports every failure on stderr; do not repeat the error
	// here, or failures would print twice.
	code, _ := attest.Exec(s, *broker, *cred, *envVar, *field, childArgv)
	return code
}

// execHelpBody returns the `exec` flag, usage, and exit-code reference. It is
// the ONE copy, the same pattern headersHelpBody() established: helpText()
// embeds it for `signet --help`, and runExec installs execUsage as the
// FlagSet's Usage for `signet exec --help`, so the two cannot drift.
func execHelpBody() string {
	return `Exec flags:
  signet exec [flags] --broker <url> --credential <name> --env-var <NAME> -- <command> [args...]
  --broker      <url>    broker URL (required)
  --credential  <name>   credential name to vend (required)
  --env-var     <NAME>   environment variable name to set on the child process (required)
  --field       <name>   static field to set (required when the credential
                          has more than one static field; ignored for
                          session material, which always sets access_token)

The "--" separates signet's own flags from the child command's; everything
after it is passed to <command> untouched, never parsed by signet.

exec vends the credential, sets --env-var to its value in the CHILD's
environment only (never signet's own, never a shell variable, never a file),
and replaces this process with <command> via syscall.Exec — the same
process-image-replacement primitive git and ssh-agent style helpers use, so
there is no signet parent process left holding the value in memory and no
extra hop in the child's stdio. Nothing is printed to stdout on success:
stdout belongs to <command>, which is typically about to speak a protocol
(e.g. MCP stdio) on it.

Example — launch a stdio MCP server with a broker-vended token in its
environment, without the token ever touching this shell:

  signet exec --broker https://broker.example.internal --credential github-pat \
    --env-var GITHUB_PERSONAL_ACCESS_TOKEN -- github-mcp-server stdio

Exec exit codes:
  0  success — never actually returned; syscall.Exec replaces this process
  2  key missing — no key enrolled for this identity
  3  attestation rejected — broker refused the attestation
  4  credential out of scope — identity exists but credential is not in its scope
  5  credential not found — credential name absent from the catalogue
  6  unusable material — credential cannot be resolved to a single field's value
  7  command not found — <command> could not be resolved to an executable on PATH

`
}

// execUsage is the FlagSet Usage for `signet exec`. flag prints Usage on
// -h/--help and then returns ErrHelp, so without this the subcommand's help
// is only flag's own bare list of flags — never the "--" contract or the
// worked example a caller needs before wiring this into a real command.
func execUsage() {
	fmt.Fprint(os.Stderr, `signet exec — attest, vend a credential, set it as an env var, and exec a command

Usage:
  signet exec [flags] --broker <url> --credential <name> --env-var <NAME> -- <command> [args...]

`+execHelpBody()+`Backend selection flags (--backend, --slot, --identity, --agent): signet --help
`)
}
