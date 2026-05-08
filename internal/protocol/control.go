package protocol

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

type CommandType int

const (
	CommandBlock CommandType = iota
	CommandUnblock
	CommandListBlocks
	CommandListRecords
	CommandQuery
	CommandMode
	CommandStats
	CommandClearCache
	CommandHelp
)

type Cmd struct {
	cmdType CommandType
	strLen  int // length of the command string, 0 or more
}

type Command struct {
	Type   CommandType
	Name   string
	Domain string
	QType  uint16
	Mode   string
}

var commandSpecs = map[string]Cmd{
	"b":       {cmdType: CommandBlock, strLen: 1},
	"block":   {cmdType: CommandBlock, strLen: 1},
	"ub":      {cmdType: CommandUnblock, strLen: 1},
	"unblock": {cmdType: CommandUnblock, strLen: 1},
	"lb":      {cmdType: CommandListBlocks, strLen: 0},
	"lr":      {cmdType: CommandListRecords, strLen: 0},
	//"q":          {cmdType: CommandQuery, strLen: 2},
	//"clearcache": {cmdType: CommandClearCache, strLen: 0},
	// "mode": {cmdType: CommandMode, strLen: 0},
	// "stats": {cmdType: CommandStats, strLen: 0},
	// "help": {cmdType: CommandHelp, strLen: 0},
}

func ParseCommand(line string) (Command, error) {
	// Plain whitespace commands are enough for this controller.
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return Command{}, errors.New("empty command")
	}

	token := strings.ToLower(fields[0])
	spec, ok := commandSpecs[token]
	if !ok {
		return Command{}, fmt.Errorf("unknown command %q", fields[0])
	}
	if len(fields)-1 != spec.strLen {
		return Command{}, fmt.Errorf("usage: %s", usageFor(spec.cmdType))
	}

	cmd := Command{
		Type: spec.cmdType,
		Name: nameFor(spec.cmdType),
	}

	switch spec.cmdType {
	case CommandBlock, CommandUnblock:
		cmd.Domain = fields[1]
	case CommandQuery:
		cmd.Domain = fields[1]
		qtype, ok := dns.StringToType[strings.ToUpper(fields[2])]
		if !ok {
			return Command{}, fmt.Errorf("unknown DNS type %q", fields[2])
		}
		cmd.QType = qtype
	}

	return cmd, nil
}

func nameFor(cmdType CommandType) string {
	switch cmdType {
	case CommandBlock:
		return "block"
	case CommandUnblock:
		return "unblock"
	case CommandListBlocks:
		return "lb"
	case CommandListRecords:
		return "lr"
	//case CommandQuery:
	//	return "q"
	//case CommandMode:
	//	return "mode"
	//case CommandStats:
	//	return "stats"
	//case CommandClearCache:
	//	return "clearcache"
	case CommandHelp:
		return "help"
	default:
		return ""
	}
}

func usageFor(cmdType CommandType) string {
	switch cmdType {
	case CommandBlock:
		return "block DOMAIN"
	case CommandUnblock:
		return "unblock DOMAIN"
	case CommandListBlocks:
		return "lb"
	case CommandListRecords:
		return "lr"
	//case CommandQuery:
	//	return "q DOMAIN TYPE"
	//case CommandClearCache:
	//	return "clearcache"
	case CommandHelp:
		return "help"
	default:
		return nameFor(cmdType)
	}
}

func Help() string {
	// Keep this near the parser order.
	return strings.Join([]string{
		"b DOMAIN",
		"block DOMAIN",
		"ub DOMAIN",
		"unblock DOMAIN",
		"lb",
		"lr",
		//"q DOMAIN TYPE",
		// "mode",
		// "mode forward",
		// "mode iterative",
		// "stats",
		//"clearcache",
	}, "\n")
}
