package main

import (
	goblkid "github.com/isi-lincoln/goblkid/wipefs"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func main() {
	// verbose is the logging level debug
	var verbose bool

	root := &cobra.Command{
		Use:   "goblkid",
		Short: "Interact with miniature go libblkid",
	}

	get := &cobra.Command{
		Use:   "get",
		Short: "get things",
	}
	root.AddCommand(get)

	wipe := &cobra.Command{
		Use:   "wipe",
		Short: "wipe things",
	}
	root.AddCommand(wipe)

	getInfo := &cobra.Command{
		Use:   "info [device]",
		Short: "Get block device information",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			info, err := goblkid.GetProbeInfo(args[0])
			if err != nil {
				log.Fatal(err)
			}
			goblkid.PrintProbeInfo(info)
		},
	}
	get.AddCommand(getInfo)

	// GET COMMANDS
	wipeFS := &cobra.Command{
		Use:   "fs [device]",
		Short: "Get block device information",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			err := goblkid.WipeFileSystemSignature(args[0])
			if err != nil {
				log.Fatal(err)
			}
		},
	}
	wipe.AddCommand(wipeFS)

	root.PersistentFlags().BoolVarP(
		&verbose, "verbose", "v", false, "verbose output")

	if verbose {
		log.SetLevel(log.DebugLevel)
	}

	err := root.Execute()
	if err != nil {
		log.Fatal(err)
	}
}
