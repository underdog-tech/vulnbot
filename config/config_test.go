package config

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
	icon, err := GetIconForSeverity("High", severities)
	assert.Equal(t, icon, ":high:")
	assert.Nil(t, err)
}

func TestGetIconForUnconfiguredSeverity(t *testing.T) {
	severities := []SeverityConfig{
		{Label: "High", Slack_emoji: ":high:"},
		{Label: "Low", Slack_emoji: ":low:"},
	}
	icon, err := GetIconForSeverity("Medium", severities)
	assert.Empty(t, icon)
	assert.Error(t, err)
}

func TestGetIconForConfiguredEcosystem(t *testing.T) {
	ecosystems := []EcosystemConfig{
		{Label: "Pip", Slack_emoji: ":python:"},
		{Label: "Go", Slack_emoji: ":golang:"},
	}
	icon, err := GetIconForEcosystem("Pip", ecosystems)
	assert.Equal(t, icon, ":python:")
	assert.Nil(t, err)
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

func TestLoadConfig(t *testing.T) {
	expectedSlackChannel := "testing_slack_channel"
	currentDir, err := getCurrentDir()
	if err != nil {
		assert.Error(t, err)
	}
	testDataPath := filepath.Join(currentDir, "/testdata/test_config.toml")

	viper := NewViper()
	var config Config
	viper.LoadConfig(ViperParams{
		Output:     &config,
		ConfigPath: &testDataPath,
	})

	assert.IsType(t, Config{}, config)
	assert.Equal(t, expectedSlackChannel, config.Default_slack_channel)
}

func TestLoadEnv(t *testing.T) {
	expectedSlackAuthToken := "testing"
	currentDir, err := getCurrentDir()
	if err != nil {
		assert.Error(t, err)
	}
	testDataPath := filepath.Join(currentDir, "/testdata/config.env")

	viper := NewViper()
	var env Env
	viper.LoadEnv(ViperParams{
		EnvFileName: &testDataPath,
		Output: &env,
	})

	assert.IsType(t, Env{}, env)
	assert.Equal(t, expectedSlackAuthToken, env.SlackAuthToken)
}
