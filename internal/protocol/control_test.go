package protocol

import (
	"testing"

	"github.com/miekg/dns"
)

func TestParseBlockCommand(t *testing.T) {
	cmd, err := ParseCommand("block example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Type != CommandBlock || cmd.Name != "block" || cmd.Domain != "example.com" {
		t.Fatalf("unexpected command: %+v", cmd)
	}
}

func TestParseModeCommandDisabled(t *testing.T) {
	if _, err := ParseCommand("mode iterative"); err == nil {
		t.Fatal("mode should stay disabled until server support is ready")
	}
}

func TestParseQueryCommand(t *testing.T) {
	cmd, err := ParseCommand("q _sip._tcp.example.com SRV")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Type != CommandQuery || cmd.Name != "q" || cmd.Domain != "_sip._tcp.example.com" || cmd.QType != dns.TypeSRV {
		t.Fatalf("unexpected command: %+v", cmd)
	}
}

func TestParseStatsCommandDisabled(t *testing.T) {
	if _, err := ParseCommand("stats"); err == nil {
		t.Fatal("stats should stay disabled until server support is ready")
	}
}

func TestParseHelpCommandDisabled(t *testing.T) {
	if _, err := ParseCommand("help"); err == nil {
		t.Fatal("help should stay on the controller side")
	}
}

func TestInvalidCommand(t *testing.T) {
	if _, err := ParseCommand("bogus"); err == nil {
		t.Fatal("expected invalid command error")
	}
}
