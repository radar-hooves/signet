package main

import (
	"flag"
	"io"
	"os"
	"strings"
	"testing"
)

// TestHelpText verifies the help block mentions all subcommands.
func TestHelpText(t *testing.T) {
	text := helpText()
	for _, sub := range []string{"enrol", "sign", "auth", "verify", "headers", "vend-to-file", "exec", "agent", "version", "doctor"} {
		if !strings.Contains(text, sub) {
			t.Errorf("helpText() does not mention %q", sub)
		}
	}
}

// TestBindList verifies the repeatable --bind flag accumulator.
func TestBindList(t *testing.T) {
	var b bindList
	if err := b.Set("/run/signet/a.sock=9c"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := b.Set("/run/signet/b.sock=9d"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if len(b) != 2 {
		t.Fatalf("len = %d, want 2", len(b))
	}
	if got := b.String(); got != "/run/signet/a.sock=9c,/run/signet/b.sock=9d" {
		t.Errorf("String() = %q", got)
	}
}

// TestEnvOr pins envOr's precedence: a non-empty env var wins over the
// fallback, an explicitly-empty one is treated as unset, and an unset one
// changes nothing.
func TestEnvOr(t *testing.T) {
	const key = "SIGNET_TEST_ENVOR"

	t.Setenv(key, "from-env")
	if got := envOr(key, "fallback"); got != "from-env" {
		t.Errorf("envOr with env set = %q, want %q", got, "from-env")
	}

	t.Setenv(key, "")
	if got := envOr(key, "fallback"); got != "fallback" {
		t.Errorf("envOr with env set empty = %q, want fallback %q", got, "fallback")
	}

	os.Unsetenv(key)
	if got := envOr(key, "fallback"); got != "fallback" {
		t.Errorf("envOr with env unset = %q, want fallback %q", got, "fallback")
	}
}

// TestSignerFlagsEnvDefaults pins the three-way precedence signerFlags must
// give --backend/--slot/--identity: an explicit flag always wins, a set
// SIGNET_* env var is the default when the flag is absent, and an unset env
// var falls through to the built-in default (auto-detect/empty) unchanged.
// This is the fix for the fleet's stdio MCP entries (github, aws on atlas),
// whose literal args array cannot splat a host-only --slot the way a shell
// string can, so the host must be able to name it once in its environment.
func TestSignerFlagsEnvDefaults(t *testing.T) {
	parse := func(t *testing.T, args []string) (backend, slot, identity string) {
		t.Helper()
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		b, s, i, _ := signerFlags(fs)
		if err := fs.Parse(args); err != nil {
			t.Fatalf("Parse: %v", err)
		}
		return *b, *s, *i
	}

	t.Run("env beats built-in default", func(t *testing.T) {
		t.Setenv("SIGNET_BACKEND", "piv")
		t.Setenv("SIGNET_SLOT", "93")
		t.Setenv("SIGNET_IDENTITY", "github-mcp")
		backend, slot, identity := parse(t, nil)
		if backend != "piv" || slot != "93" || identity != "github-mcp" {
			t.Errorf("backend=%q slot=%q identity=%q, want piv/93/github-mcp", backend, slot, identity)
		}
	})

	t.Run("flag beats env", func(t *testing.T) {
		t.Setenv("SIGNET_BACKEND", "piv")
		t.Setenv("SIGNET_SLOT", "93")
		t.Setenv("SIGNET_IDENTITY", "github-mcp")
		backend, slot, identity := parse(t, []string{"--backend", "secure-enclave", "--slot", "9c", "--identity", "deploy"})
		if backend != "secure-enclave" || slot != "9c" || identity != "deploy" {
			t.Errorf("backend=%q slot=%q identity=%q, want secure-enclave/9c/deploy", backend, slot, identity)
		}
	})

	t.Run("unset env changes nothing", func(t *testing.T) {
		os.Unsetenv("SIGNET_BACKEND")
		os.Unsetenv("SIGNET_SLOT")
		os.Unsetenv("SIGNET_IDENTITY")
		backend, slot, identity := parse(t, nil)
		if backend != "" || slot != "" || identity != "" {
			t.Errorf("backend=%q slot=%q identity=%q, want all empty (auto-detect / built-in defaults)", backend, slot, identity)
		}
	})
}

// TestRunHeadersFlagValidation pins the cmd-layer gate for `headers`: the
// required/enum/non-empty checks must all fail fast (exit 1) before any
// signer or network work happens.
func TestRunHeadersFlagValidation(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"missing broker", []string{"--credential", "example-api"}},
		{"missing credential", []string{"--broker", "https://broker.internal"}},
		{"empty header", []string{"--broker", "https://broker.internal", "--credential", "example-api", "--header", " "}},
		{"bogus format", []string{"--broker", "https://broker.internal", "--credential", "example-api", "--format", "bogus"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runHeaders(tc.args); got != 1 {
				t.Errorf("runHeaders(%v) = %d, want 1", tc.args, got)
			}
		})
	}
}

// captureStderr runs f with os.Stderr redirected to a pipe and returns what was
// written. runHeaders reports every refusal there.
func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	f()
	w.Close()
	os.Stderr = old
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stderr: %v", err)
	}
	return string(b)
}

// TestRunHeadersBareWithHeaderRefused verifies --header with --bare is refused
// rather than silently ignored (--bare prints no header name, so the flag could
// not be honoured).
//
// It asserts the refusal MESSAGE, not just the exit code. Exit 1 alone proves
// nothing here: with the refusal removed, runHeaders falls through to
// selectSigner, which also exits 1 on a machine with no key enrolled — so a
// code-only assertion passes against unfixed code, for the wrong reason. The
// message is what distinguishes "refused the flag" from "no hardware".
func TestRunHeadersBareWithHeaderRefused(t *testing.T) {
	args := []string{"--broker", "https://broker.internal", "--credential", "example-api", "--bare", "--header", "X-Api-Key"}
	var code int
	stderr := captureStderr(t, func() {
		code = runHeaders(args)
	})
	if code != 1 {
		t.Errorf("runHeaders(%v) = %d, want 1", args, code)
	}
	if !strings.Contains(stderr, "--header cannot be combined with --bare") {
		t.Errorf("stderr = %q, want the --header/--bare refusal; a bare exit 1 may only mean selectSigner failed", stderr)
	}
}

// TestRunHeadersBareAloneNotRefused is the other half: --bare WITHOUT --header
// must not trip the refusal. --header carries a non-empty default, so a
// refusal keyed on the value rather than on the flag being set would reject
// every plain --bare call — the mirror-image bug.
func TestRunHeadersBareAloneNotRefused(t *testing.T) {
	args := []string{"--broker", "https://broker.internal", "--credential", "example-api", "--bare"}
	stderr := captureStderr(t, func() {
		runHeaders(args)
	})
	if strings.Contains(stderr, "cannot be combined") {
		t.Errorf("stderr = %q, want no refusal for --bare without --header", stderr)
	}
}

// TestIsFlagSet pins the explicit-vs-default distinction the --bare/--header
// refusal rests on: --header carries a non-empty default ("Authorization"), so
// a value check cannot tell "set to the default" from "not set", and refusing
// on the default would break every plain `--bare` call.
func TestIsFlagSet(t *testing.T) {
	newFS := func() (*flag.FlagSet, *string) {
		fs := flag.NewFlagSet("headers", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		header := fs.String("header", "Authorization", "")
		fs.Bool("bare", false, "")
		return fs, header
	}

	fs, header := newFS()
	if err := fs.Parse([]string{"--bare"}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if isFlagSet(fs, "header") {
		t.Error("isFlagSet(header) = true when --header was not passed")
	}
	if *header != "Authorization" {
		t.Errorf("header = %q, want the default to still apply", *header)
	}

	// Passing the default value explicitly still counts as set: the user typed
	// it, so the contradiction with --bare is real and must be reported.
	fs, _ = newFS()
	if err := fs.Parse([]string{"--header", "Authorization"}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !isFlagSet(fs, "header") {
		t.Error("isFlagSet(header) = false when --header was passed explicitly")
	}
}

// headersOutputShapeDocs are the strings issue #5 requires the help to show:
// every mode's output shape, plus a worked interpolation example.
var headersOutputShapeDocs = []string{
	`{"Authorization":"Bearer s3cr3t"}`, // default
	`{"Authorization":"s3cr3t"}`,        // --format raw
	"Bearer s3cr3t",                     // --bare
	"--bare --format raw",               // the bare-token mode
	"curl -H",                           // the interpolation example
}

// TestRunHeadersHelpDocumentsOutputShapes pins issue #5's documentation half
// against the LITERAL command its acceptance criterion names: `signet headers
// --help`.
//
// It drives runHeaders rather than reading helpText(), because those are
// different code paths and only this one is what a user actually runs. flag
// prints the FlagSet's Usage and returns ErrHelp, so a subcommand with no
// custom Usage shows only flag's bare list of flags — helpText() is never
// reached. Asserting on helpText() therefore passes while `signet headers
// --help` shows nothing of the sort: the criterion looks met and is not.
func TestRunHeadersHelpDocumentsOutputShapes(t *testing.T) {
	for _, flagName := range []string{"--help", "-h"} {
		t.Run(flagName, func(t *testing.T) {
			var code int
			out := captureStderr(t, func() {
				code = runHeaders([]string{flagName})
			})
			if code != 0 {
				t.Errorf("runHeaders([%q]) = %d, want 0 (help is not an error)", flagName, code)
			}
			for _, shape := range headersOutputShapeDocs {
				if !strings.Contains(out, shape) {
					t.Errorf("`signet headers %s` does not document output shape %q", flagName, shape)
				}
			}
		})
	}
}

// TestHelpTextDocumentsHeadersOutputShapes pins the same shapes in the
// top-level `signet --help`, which embeds the same single source.
func TestHelpTextDocumentsHeadersOutputShapes(t *testing.T) {
	text := helpText()
	for _, shape := range headersOutputShapeDocs {
		if !strings.Contains(text, shape) {
			t.Errorf("helpText() does not document headers output shape %q", shape)
		}
	}
}

// TestRunVendToFileFlagValidation pins the cmd-layer gate for `vend-to-file`:
// the required/octal checks must all fail fast (exit 1) before any signer or
// network work happens.
func TestRunVendToFileFlagValidation(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"missing broker", []string{"my-cred", "/tmp/dest"}},
		{"missing name and dest", []string{"--broker", "https://broker.internal"}},
		{"missing dest", []string{"--broker", "https://broker.internal", "my-cred"}},
		{"bogus mode", []string{"--broker", "https://broker.internal", "--mode", "not-octal", "my-cred", "/tmp/dest"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runVendToFile(tc.args); got != 1 {
				t.Errorf("runVendToFile(%v) = %d, want 1", tc.args, got)
			}
		})
	}
}

// TestParseFileMode verifies octal file-mode flag parsing, with and without
// a leading zero, and rejects non-octal input.
func TestParseFileMode(t *testing.T) {
	cases := []struct {
		input string
		want  int
	}{
		{"0600", 0o600},
		{"600", 0o600},
		{"0640", 0o640},
		{"0400", 0o400},
		{"07777", 0o7777}, // the top of the 12-bit POSIX permission/sticky/setuid/setgid range
	}
	for _, tc := range cases {
		got, err := parseFileMode(tc.input)
		if err != nil {
			t.Fatalf("parseFileMode(%q): %v", tc.input, err)
		}
		if int(got) != tc.want {
			t.Errorf("parseFileMode(%q) = %o, want %o", tc.input, got, tc.want)
		}
	}

	if _, err := parseFileMode("not-octal"); err == nil {
		t.Error("expected error for non-octal mode, got nil")
	}
	if _, err := parseFileMode("999"); err == nil {
		t.Error("expected error for out-of-range octal digits, got nil")
	}

	// A mode past the 12-bit POSIX range must be rejected with a clear
	// "out of range" error, not silently truncated by os.Chmod into a
	// confusing "----------" dest (the footgun this bound closes).
	rangeCases := []string{"010000", "20000000000"}
	for _, in := range rangeCases {
		_, err := parseFileMode(in)
		if err == nil {
			t.Errorf("parseFileMode(%q): expected an out-of-range error, got nil", in)
			continue
		}
		if !strings.Contains(err.Error(), "out of range") {
			t.Errorf("parseFileMode(%q) error = %q, want it to mention \"out of range\"", in, err.Error())
		}
	}
}

// TestRunExecFlagValidation pins the cmd-layer gate for `exec`: the missing
// "--" separator, the missing-command-after-"--" case, and the required
// (--broker/--credential/--env-var) checks must all fail fast (exit 1)
// before any signer or network work happens.
func TestRunExecFlagValidation(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"missing -- entirely", []string{"--broker", "https://broker.internal", "--credential", "my-cred", "--env-var", "MY_TOKEN"}},
		{"missing command after --", []string{"--broker", "https://broker.internal", "--credential", "my-cred", "--env-var", "MY_TOKEN", "--"}},
		{"missing broker", []string{"--credential", "my-cred", "--env-var", "MY_TOKEN", "--", "true"}},
		{"missing credential", []string{"--broker", "https://broker.internal", "--env-var", "MY_TOKEN", "--", "true"}},
		{"missing env-var", []string{"--broker", "https://broker.internal", "--credential", "my-cred", "--", "true"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runExec(tc.args); got != 1 {
				t.Errorf("runExec(%v) = %d, want 1", tc.args, got)
			}
		})
	}
}

// TestRunExecMissingSeparatorMessage pins the missing-"--" refusal message
// specifically, distinguishing it from every other exit-1 cause: a bare
// exit 1 could equally mean a missing required flag, so the message is what
// proves the RIGHT check fired.
func TestRunExecMissingSeparatorMessage(t *testing.T) {
	args := []string{"--broker", "https://broker.internal", "--credential", "my-cred", "--env-var", "MY_TOKEN"}
	stderr := captureStderr(t, func() {
		runExec(args)
	})
	if !strings.Contains(stderr, "missing -- separator") {
		t.Errorf("stderr = %q, want the missing -- separator refusal", stderr)
	}
}

// TestRunExecMissingCommandMessage pins the missing-command refusal message
// for the case where "--" is present but nothing follows it.
func TestRunExecMissingCommandMessage(t *testing.T) {
	args := []string{"--broker", "https://broker.internal", "--credential", "my-cred", "--env-var", "MY_TOKEN", "--"}
	stderr := captureStderr(t, func() {
		runExec(args)
	})
	if !strings.Contains(stderr, "a command is required after --") {
		t.Errorf("stderr = %q, want the missing-command refusal", stderr)
	}
}

// TestRunExecHelpWithoutSeparator verifies `signet exec --help` (or -h) works
// even with no "--" present — the help check must run before the
// missing-separator refusal, or a caller could never discover the "--"
// contract exists in the first place.
func TestRunExecHelpWithoutSeparator(t *testing.T) {
	for _, flagName := range []string{"--help", "-h"} {
		t.Run(flagName, func(t *testing.T) {
			var code int
			out := captureStderr(t, func() {
				code = runExec([]string{flagName})
			})
			if code != 0 {
				t.Errorf("runExec([%q]) = %d, want 0 (help is not an error)", flagName, code)
			}
			if !strings.Contains(out, "--") {
				t.Errorf("runExec(%q) help output = %q, want it to document the -- separator", flagName, out)
			}
		})
	}
}

// TestRunExecFlagsAfterSeparatorNotParsedBySignet verifies that a flag-shaped
// token after "--" (e.g. "--broker") is treated as part of the CHILD's argv,
// never re-parsed by signet's own FlagSet. It drives this through the same
// missing-command / required-flag gates as the other tests here: passing
// "--broker" as the child's argv[0] must not be swallowed as a second
// occurrence of signet's own --broker flag (which would either error
// differently or silently override the first), so the run must get past
// every cmd-layer validation check and fail for a different reason further
// down (no hardware key enrolled, or an unreachable broker) — never for one
// of the flag-validation messages pinned above.
//
// The broker URL is the same unreachable loopback address the sibling
// key-missing tests use (127.0.0.1:0): it fails fast without a real network
// call or a DNS lookup, and never actually needs to be reached, because this
// test only cares that signet's OWN parsing was not re-triggered.
func TestRunExecFlagsAfterSeparatorNotParsedBySignet(t *testing.T) {
	args := []string{"--broker", "http://127.0.0.1:0", "--credential", "my-cred", "--env-var", "MY_TOKEN", "--", "--broker", "not-a-flag-here"}
	stderr := captureStderr(t, func() {
		runExec(args)
	})
	if strings.Contains(stderr, "missing -- separator") || strings.Contains(stderr, "a command is required after --") || strings.Contains(stderr, "--broker is required") {
		t.Errorf("stderr = %q, want signet's own flag parsing to be untouched by the child's \"--broker\" argv[0]", stderr)
	}
}
