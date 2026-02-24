package main

import (
	"os"

	"github.com/fzymgc-house/router-hosts/internal/client/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		os.Exit(1)
	}
}
