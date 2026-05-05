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
	if cmd.Name != "block" || cmd.Domain != "example.com" {
		t.Fatalf("unexpected command: %+v", cmd)
	}
}

func TestParseModeCommand(t *testing.T) {
	cmd, err := ParseCommand("mode iterative")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Name != "mode" || cmd.Mode != "iterative" {
		t.Fatalf("unexpected command: %+v", cmd)
	}
}

func TestParseQueryCommand(t *testing.T) {
	cmd, err := ParseCommand("q _sip._tcp.example.com SRV")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Name != "q" || cmd.Domain != "_sip._tcp.example.com" || cmd.QType != dns.TypeSRV {
		t.Fatalf("unexpected command: %+v", cmd)
	}
}

func TestInvalidCommand(t *testing.T) {
	if _, err := ParseCommand("bogus"); err == nil {
		t.Fatal("expected invalid command error")
	}
}
