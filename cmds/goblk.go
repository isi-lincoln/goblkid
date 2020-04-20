package main

import (
	//"github.com/isi-lincoln/goblkid"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	// verbose is the logging level debug
	verbose bool
)

func main() {

	root := &cobra.Command{
		Use:   "goblkid",
		Short: "Interact go libblkid",
	}

	add := &cobra.Command{
		Use:   "add",
		Short: "add things",
	}
	root.AddCommand(add)

	get := &cobra.Command{
		Use:   "get",
		Short: "get things",
	}
	root.AddCommand(get)

	list := &cobra.Command{
		Use:   "list",
		Short: "list things",
	}
	root.AddCommand(list)

	// GET COMMANDS
	getMac := &cobra.Command{
		Use:   "command [mac]",
		Short: "Get command for mac",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			//GetCommand(args[0])
		},
	}
	get.AddCommand(getMac)

	getID := &cobra.Command{
		Use:   "id [mac]",
		Short: "Get id of mac addr",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			//GetID(args[0])
		},
	}
	get.AddCommand(getID)

	root.PersistentFlags().BoolVarP(
		&verbose, "verbose", "v", false, "verbose output")

	if verbose {
		log.SetLevel(log.DebugLevel)
	}

	root.Execute()
}
