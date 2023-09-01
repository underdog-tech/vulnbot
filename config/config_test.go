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

func TestLoadConfig(t *testing.T) {
	expectedSlackChannel := "testing_slack_channel"
	currentDir, err := getCurrentDir()
	if err != nil {
		assert.Error(t, err)
	}
	testDataPath := filepath.Join(currentDir, "/testdata/test_config.toml")

	var cfg config.Config
	_ = config.LoadConfig(config.ViperParams{
		Output:     &cfg,
		ConfigPath: &testDataPath,
	})

	assert.IsType(t, config.Config{}, cfg)
	assert.Equal(t, expectedSlackChannel, cfg.Default_slack_channel)
}

func TestLoadEnv(t *testing.T) {
	expectedSlackAuthToken := "testing"
	currentDir, err := getCurrentDir()
	if err != nil {
		assert.Error(t, err)
	}
	testDataPath := filepath.Join(currentDir, "/testdata/config.env")

	var env config.Env
	_ = config.LoadEnv(config.ViperParams{
		EnvFileName: &testDataPath,
		Output:      &env,
	})

	assert.IsType(t, config.Env{}, env)
	assert.Equal(t, expectedSlackAuthToken, env.SlackAuthToken)
}
