package cli

import (
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/chzyer/readline"
	"github.com/spf13/cobra"
)

func REPL() {
	// Create a new readline instance.
	repl := replInitialize()
	defer func(repl *readline.Instance) {
		if err := repl.Close(); err != nil {
			log.Printf("Fail to close readline: %s\n", err)
		}
	}(repl)

	rootCmd := commandInitialize()

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
		HistoryFile:       "/tmp/dnsctl.history",
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

func commandInitialize() *cobra.Command {
	rootCmd := &cobra.Command{
		Use: "dnsctl",
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
			fmt.Println("blocklist add called with ", args)
			return nil
		},
	}
	blocklistCmd.AddCommand(blocklistAddCmd)

	blocklistRemoveCmd := &cobra.Command{
		Use:   "remove <domain>",
		Short: "Remove domain from blocklist",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("blocklist remove called with ", args)
			return nil
		},
	}
	blocklistCmd.AddCommand(blocklistRemoveCmd)

	blocklistListCmd := &cobra.Command{
		Use:   "list",
		Short: "List all domains in blocklist",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("blocklist list called with ", args)
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
			fmt.Println("cache list called with ", args)
			return nil
		},
	}
	cacheCmd.AddCommand(cacheListCmd)

	return rootCmd
}
