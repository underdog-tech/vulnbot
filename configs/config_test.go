package configs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetIconForConfiguredSeverity(t *testing.T) {
	severities := []SeverityConfig{
		{Label: "High", Slack_emoji: ":high:"},
		{Label: "Low", Slack_emoji: ":low:"},
	}
	icon := GetIconForSeverity(FindingSeverityHigh, severities)
	assert.Equal(t, icon, ":high:")
}

func TestGetIconForUnconfiguredSeverity(t *testing.T) {
	severities := []SeverityConfig{
		{Label: "High", Slack_emoji: ":high:"},
		{Label: "Low", Slack_emoji: ":low:"},
	}
	icon := GetIconForSeverity(FindingSeverityModerate, severities)
	assert.Equal(t, DEFAULT_SLACK_ICON, icon)
}

func TestGetIconForConfiguredEcosystem(t *testing.T) {
	ecosystems := []EcosystemConfig{
		{Label: "Python", Slack_emoji: ":python:"},
		{Label: "Go", Slack_emoji: ":golang:"},
	}
	icon := GetIconForEcosystem(FindingEcosystemPython, ecosystems)
	assert.Equal(t, icon, ":python:")
	assert.NotEqual(t, ":python:", DEFAULT_SLACK_ICON)
}

func TestGetConfiguredTeamConfigBySlug(t *testing.T) {
	testersTeam := TeamConfig{Name: "Testers", Github_slug: "testers-team"}
	failersTeam := TeamConfig{Name: "Failers", Github_slug: "failers-team"}
	TeamConfigs := []TeamConfig{
		testersTeam,
		failersTeam,
	}
	team, err := GetTeamConfigBySlug("testers-team", TeamConfigs)
	assert.Equal(t, team, testersTeam)
	assert.Nil(t, err)
}

func TestGetUnconfiguredTeamConfigBySlug(t *testing.T) {
	TeamConfigs := []TeamConfig{} // Empty is easiest for this purpose
	team, err := GetTeamConfigBySlug("unknown-team", TeamConfigs)
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
	cfg, err := GetUserConfig(testDataPath)
	assert.Nil(t, err)
	assert.Equal(t, "testing_slack_channel", cfg.Default_slack_channel)
	assert.Equal(t, []EcosystemConfig{{Label: "Go", Slack_emoji: ":golang:"}}, cfg.Ecosystem)
}

func TestGetUserConfigFromEnv(t *testing.T) {
	SetConfigDefaults()

	t.Setenv("VULNBOT_REPORTERS", "slack")
	t.Setenv("VULNBOT_GITHUB_ORG", "hitchhikers")
	// This should override the config file
	t.Setenv("VULNBOT_DEFAULT_SLACK_CHANNEL", "other_slack_channel")

	currentDir, err := getCurrentDir()
	assert.Nil(t, err)
	testDataPath := filepath.Join(currentDir, "/testdata/test_config.toml")
	cfg, err := GetUserConfig(testDataPath)
	assert.Nil(t, err)

	assert.Equal(t, []string{"slack"}, cfg.Reporters)
	assert.Equal(t, "hitchhikers", cfg.Github_org)
	assert.Equal(t, "other_slack_channel", cfg.Default_slack_channel)
}
