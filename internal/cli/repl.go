package cli

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"github.com/ShawnSjl/DNS-Resolver/internal/protocol"
	"github.com/chzyer/readline"
	"github.com/spf13/cobra"
)

func REPL(conn *net.TCPConn) {
	// Create a new readline instance.
	repl := replInitialize()
	defer func(repl *readline.Instance) {
		if err := repl.Close(); err != nil {
			log.Printf("Fail to close readline: %s\n", err)
		}
	}(repl)

	rootCmd := commandInitialize(conn)

	for {
		// Get the line from the readline instance.
		line, done := replGetLine(repl)
		if done {
			break
		}

		// ignore empty line
		if line == "" {
			continue
		}

		// exit command
		if line == "exit" {
			break
		}

		// Remove the command name from the line.
		tokens := strings.Fields(line)
		if tokens[0] == rootCmd.Name() {
			tokens = tokens[1:]
		}
		if len(tokens) == 0 {
			continue
		}

		// Let cobra handle the command.
		rootCmd.SetArgs(tokens)
		if err := rootCmd.Execute(); err != nil {
		}
	}
}

// replInitialize initialize the readline instance.
func replInitialize() *readline.Instance {
	l, err := readline.NewEx(&readline.Config{
		Prompt:            "> ",
		HistoryFile:       "/tmp/dnr.history",
		InterruptPrompt:   "^C",
		HistorySearchFold: true,
		EOFPrompt:         "exit",
	})
	if err != nil {
		panic(err)
	}
	return l
}

// replGetLine get the line from the readline instance.
func replGetLine(repl *readline.Instance) (string, bool) {
	line, err := repl.Readline()
	if errors.Is(err, readline.ErrInterrupt) {
		return "", true
	} else if err == io.EOF {
		return "", true
	}

	line = strings.TrimSpace(line)

	return line, false
}

// ******************** Command **********************

func commandInitialize(conn *net.TCPConn) *cobra.Command {
	rootCmd := &cobra.Command{
		Use: "dnr",
	}
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	// Blocklist
	var blocklistCmd = &cobra.Command{
		Use:     "block",
		Short:   "Domain blocklist",
		Aliases: []string{"b"},
	}
	rootCmd.AddCommand(blocklistCmd)

	blocklistAddCmd := &cobra.Command{
		Use:   "add <domain>",
		Short: "Add domain to blocklist",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data := []byte(args[0])
			msg := protocol.Message{
				MsgType: protocol.MsgBlockAdd,
				Data:    data,
			}
			if err := sendAndReceive(conn, msg); err != nil {
				return err
			}
			return nil
		},
	}
	blocklistCmd.AddCommand(blocklistAddCmd)

	blocklistRemoveCmd := &cobra.Command{
		Use:   "remove <domain>",
		Short: "Remove domain from blocklist",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data := []byte(args[0])
			msg := protocol.Message{
				MsgType: protocol.MsgBlockRemove,
				Data:    data,
			}
			if err := sendAndReceive(conn, msg); err != nil {
				return err
			}
			return nil
		},
	}
	blocklistCmd.AddCommand(blocklistRemoveCmd)

	blocklistListCmd := &cobra.Command{
		Use:   "list",
		Short: "List all domains in blocklist",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			msg := protocol.Message{
				MsgType: protocol.MsgBlockList,
				Data:    make([]byte, 0),
			}
			if err := sendAndReceive(conn, msg); err != nil {
				return err
			}
			return nil
		},
	}
	blocklistCmd.AddCommand(blocklistListCmd)

	// Cache
	cacheCmd := &cobra.Command{
		Use:     "cache",
		Short:   "DNS cache",
		Aliases: []string{"c"},
	}
	rootCmd.AddCommand(cacheCmd)

	cacheListCmd := &cobra.Command{
		Use:   "list",
		Short: "List all cached DNS records",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			msg := protocol.Message{
				MsgType: protocol.MsgCacheList,
				Data:    make([]byte, 0),
			}
			if err := sendAndReceive(conn, msg); err != nil {
				return err
			}
			return nil
		},
	}
	cacheCmd.AddCommand(cacheListCmd)

	return rootCmd
}

func sendAndReceive(conn *net.TCPConn, msg protocol.Message) error {
	// Send message through connection
	if sendErr := protocol.Send(conn, &msg); sendErr != nil {
		return sendErr
	}

	// Receive response from connection
	reply, err := protocol.Receive(conn)
	if err != nil {
		return err
	}

	// Handle response
	switch reply.MsgType {
	case protocol.MsgError:
		return fmt.Errorf("error: %s", string(reply.Data))
	case protocol.MsgAck:
		fmt.Println(string(reply.Data))
		return nil
	default:
		return fmt.Errorf("unexpected response type: %d", reply.MsgType)
	}
}
