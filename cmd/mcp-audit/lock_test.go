package main

import (
	"flag"
	"io"
	"reflect"
	"testing"
)

// The lock commands make security decisions about a specific file, so a flag
// that names that file must never be dropped on the floor. These pin the
// parsing that decides which file it is.

func newLockFlagSet() (*flag.FlagSet, *lockFlags, *bool) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var flags lockFlags
	flags.register(fs)
	all := fs.Bool("all", false, "")
	return fs, &flags, all
}

func TestFlagsAfterPositionalArgumentsAreParsed(t *testing.T) {
	// Regression: the standard flag package stops at the first positional
	// argument, so `approve demo echo --state x.json` used to approve in the
	// default store and say nothing.
	cases := [][]string{
		{"demo", "echo", "--state", "x.json"},
		{"--state", "x.json", "demo", "echo"},
		{"demo", "--state", "x.json", "echo"},
		{"demo", "echo", "--state=x.json"},
	}
	for _, args := range cases {
		fs, flags, _ := newLockFlagSet()
		rest, err := parseInterspersed(fs, args)
		if err != nil {
			t.Fatalf("%v: parse error = %v", args, err)
		}
		if flags.state != "x.json" {
			t.Errorf("%v: state = %q, want x.json", args, flags.state)
		}
		if want := []string{"demo", "echo"}; !reflect.DeepEqual(rest, want) {
			t.Errorf("%v: positionals = %v, want %v", args, rest, want)
		}
	}
}

func TestBooleanFlagAfterAPositionalIsParsed(t *testing.T) {
	fs, _, all := newLockFlagSet()
	rest, err := parseInterspersed(fs, []string{"demo", "--all"})
	if err != nil {
		t.Fatalf("parse error = %v", err)
	}
	if !*all {
		t.Error("--all after a positional argument was ignored")
	}
	if !reflect.DeepEqual(rest, []string{"demo"}) {
		t.Errorf("positionals = %v, want [demo]", rest)
	}
}

func TestDoubleDashEndsFlagParsing(t *testing.T) {
	// A server genuinely named like a flag is reachable after "--".
	fs, flags, _ := newLockFlagSet()
	rest, err := parseInterspersed(fs, []string{"--", "--state"})
	if err != nil {
		t.Fatalf("parse error = %v", err)
	}
	if flags.state != "" {
		t.Errorf("state = %q, want it unset after --", flags.state)
	}
	if !reflect.DeepEqual(rest, []string{"--state"}) {
		t.Errorf("positionals = %v, want [--state]", rest)
	}
}

func TestSurplusArgumentsAreAnErrorNotIgnored(t *testing.T) {
	if _, _, err := positional([]string{"demo", "echo", "extra"}); err == nil {
		t.Error("a third positional argument was silently ignored")
	}
	server, tool, err := positional([]string{"demo", "echo"})
	if err != nil || server != "demo" || tool != "echo" {
		t.Errorf("positional = %q, %q, %v; want demo, echo, nil", server, tool, err)
	}
}

func TestUnknownFlagIsStillAnError(t *testing.T) {
	fs, _, _ := newLockFlagSet()
	if _, err := parseInterspersed(fs, []string{"demo", "--stat", "x.json"}); err == nil {
		t.Error("a misspelt flag after a positional argument was accepted")
	}
}
