package protocol

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

type Command struct {
	Name   string
	Domain string
	QType  uint16
	Mode   string
}

func ParseCommand(line string) (Command, error) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return Command{}, errors.New("empty command")
	}

	switch strings.ToLower(fields[0]) {
	case "b", "block":
		if len(fields) != 2 {
			return Command{}, errors.New("usage: block DOMAIN")
		}
		return Command{Name: "block", Domain: fields[1]}, nil
	case "ub", "unblock":
		if len(fields) != 2 {
			return Command{}, errors.New("usage: unblock DOMAIN")
		}
		return Command{Name: "unblock", Domain: fields[1]}, nil
	case "lb":
		if len(fields) != 1 {
			return Command{}, errors.New("usage: lb")
		}
		return Command{Name: "lb"}, nil
	case "lr":
		if len(fields) != 1 {
			return Command{}, errors.New("usage: lr")
		}
		return Command{Name: "lr"}, nil
	case "q":
		if len(fields) != 3 {
			return Command{}, errors.New("usage: q DOMAIN TYPE")
		}
		qtype, ok := dns.StringToType[strings.ToUpper(fields[2])]
		if !ok {
			return Command{}, fmt.Errorf("unknown DNS type %q", fields[2])
		}
		return Command{Name: "q", Domain: fields[1], QType: qtype}, nil
	case "mode":
		if len(fields) == 1 {
			return Command{Name: "mode"}, nil
		}
		if len(fields) != 2 {
			return Command{}, errors.New("usage: mode [forward|iterative]")
		}
		mode := strings.ToLower(fields[1])
		if mode != "forward" && mode != "iterative" {
			return Command{}, fmt.Errorf("unsupported mode %q", fields[1])
		}
		return Command{Name: "mode", Mode: mode}, nil
	case "stats":
		if len(fields) != 1 {
			return Command{}, errors.New("usage: stats")
		}
		return Command{Name: "stats"}, nil
	case "clearcache":
		if len(fields) != 1 {
			return Command{}, errors.New("usage: clearcache")
		}
		return Command{Name: "clearcache"}, nil
	case "help":
		if len(fields) != 1 {
			return Command{}, errors.New("usage: help")
		}
		return Command{Name: "help"}, nil
	default:
		return Command{}, fmt.Errorf("unknown command %q", fields[0])
	}
}

func Help() string {
	return strings.Join([]string{
		"b DOMAIN",
		"block DOMAIN",
		"ub DOMAIN",
		"unblock DOMAIN",
		"lb",
		"lr",
		"q DOMAIN TYPE",
		"mode",
		"mode forward",
		"mode iterative",
		"stats",
		"clearcache",
		"help",
	}, "\n")
}
