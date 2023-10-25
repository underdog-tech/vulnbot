package config_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/underdog-tech/vulnbot/config"
)

func TestGetIconForConfiguredSeverity(t *testing.T) {
	severities := []config.SeverityConfig{
		{Label: "High", Slack_emoji: ":high:"},
		{Label: "Low", Slack_emoji: ":low:"},
	}
	icon, err := config.GetIconForSeverity(config.FindingSeverityHigh, severities)
	assert.Equal(t, icon, ":high:")
	assert.Nil(t, err)
}

func TestGetIconForUnconfiguredSeverity(t *testing.T) {
	severities := []config.SeverityConfig{
		{Label: "High", Slack_emoji: ":high:"},
		{Label: "Low", Slack_emoji: ":low:"},
	}
	icon, err := config.GetIconForSeverity(config.FindingSeverityModerate, severities)
	assert.Empty(t, icon)
	assert.Error(t, err)
}

func TestGetIconForConfiguredEcosystem(t *testing.T) {
	ecosystems := []config.EcosystemConfig{
		{Label: "Python", Slack_emoji: ":python:"},
		{Label: "Go", Slack_emoji: ":golang:"},
	}
	icon, err := config.GetIconForEcosystem(config.FindingEcosystemPython, ecosystems)
	assert.Equal(t, icon, ":python:")
	assert.Nil(t, err)
}

func TestGetConfiguredTeamConfigBySlug(t *testing.T) {
	testersTeam := config.TeamConfig{Name: "Testers", Github_slug: "testers-team"}
	failersTeam := config.TeamConfig{Name: "Failers", Github_slug: "failers-team"}
	TeamConfigs := []config.TeamConfig{
		testersTeam,
		failersTeam,
	}
	team, err := config.GetTeamConfigBySlug("testers-team", TeamConfigs)
	assert.Equal(t, team, testersTeam)
	assert.Nil(t, err)
}

func TestGetUnconfiguredTeamConfigBySlug(t *testing.T) {
	TeamConfigs := []config.TeamConfig{} // Empty is easiest for this purpose
	team, err := config.GetTeamConfigBySlug("unknown-team", TeamConfigs)
	assert.Empty(t, team)
	assert.Error(t, err)
}

func getCurrentDir() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Println("Failed to get current working directory:", err)
		return "", err
	}

	return cwd, nil
}

func TestGetUserConfigFromFile(t *testing.T) {
	currentDir, err := getCurrentDir()
	assert.Nil(t, err)
	testDataPath := filepath.Join(currentDir, "/testdata/test_config.toml")
	cfg, err := config.GetUserConfig(testDataPath)
	assert.Nil(t, err)
	assert.Equal(t, "testing_slack_channel", cfg.Default_slack_channel)
	assert.Equal(t, []config.EcosystemConfig{{Label: "Go", Slack_emoji: ":golang:"}}, cfg.Ecosystem)
}

func TestGetUserConfigFromEnv(t *testing.T) {
	t.Setenv("VULNBOT_REPORTERS", "slack")
	t.Setenv("VULNBOT_GITHUB_ORG", "hitchhikers")
	// This should override the config file
	t.Setenv("VULNBOT_DEFAULT_SLACK_CHANNEL", "other_slack_channel")

	currentDir, err := getCurrentDir()
	assert.Nil(t, err)
	testDataPath := filepath.Join(currentDir, "/testdata/test_config.toml")
	cfg, err := config.GetUserConfig(testDataPath)
	assert.Nil(t, err)

	assert.Equal(t, []string{"slack"}, cfg.Reporters)
	assert.Equal(t, "hitchhikers", cfg.Github_org)
	assert.Equal(t, "other_slack_channel", cfg.Default_slack_channel)
}
