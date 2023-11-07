package cmd_test

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/underdog-tech/vulnbot/cmd"
)

func TestNewRootCommand(t *testing.T) {
	// Mostly just ensure nothing errors out.
	c := cmd.NewRootCommand()

	assert.IsType(t, &cobra.Command{}, c)
	assert.Equal(t, "vulnbot", c.Use)
	assert.True(t, c.HasAvailableSubCommands())
}
