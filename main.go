package main

import (
	"os"

	"github.com/4nkitd/yubi-key/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args))
}
