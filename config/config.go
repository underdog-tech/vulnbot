package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/underdog-tech/vulnbot/logger"

	v "github.com/spf13/viper"
)

var viper *v.Viper

type SeverityConfig struct {
	Label       string
	Slack_emoji string
}

type EcosystemConfig struct {
	Label       string
	Slack_emoji string
}

type TeamConfig struct {
	Name          string
	Github_slug   string
	Slack_channel string
}

type TomlConfig struct {
	Default_slack_channel string
	Severity              []SeverityConfig
	Ecosystem             []EcosystemConfig
	Team                  []TeamConfig
}

type Env struct {
	GithubOrg      string `mapstructure:"GITHUB_ORG"`
	SlackAuthToken string `mapstructure:"SLACK_AUTH_TOKEN"`
	GithubToken    string `mapstructure:"GITHUB_TOKEN"`
}

func getViper() *v.Viper {
	if viper == nil {
		viper = v.New()
	}
	return viper
}

func LoadConfig(configFilePath *string) TomlConfig {
	var config TomlConfig
	log := logger.Get()

	v := getViper()

	filename := filepath.Base(*configFilePath)
	extension := filepath.Ext(*configFilePath)

	currentDir, err := os.Getwd()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get current working directory.")
	}

	v.SetConfigName(filename)
	v.AddConfigPath(currentDir)
	v.SetConfigType(strings.TrimLeft(extension, "."))

	err = v.ReadInConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to read config.")
	}

	err = v.Unmarshal(&config)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to unmarshal config.")
	}

	log.Debug().Any("config", config).Msg("Config loaded.")
	return config
}

func LoadEnv() Env {
	var env Env
	log := logger.Get()

	v := getViper()

	// Read in environment variables that match
	v.SetConfigFile(".env")
	v.AutomaticEnv()

	err := v.ReadInConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to read config.")
	}

	err = v.Unmarshal(&env)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to unmarshal config.")
	}

	log.Debug().Any("env", env).Msg("Env loaded.")
	return env
}

func GetIconForSeverity(severity string, severities []SeverityConfig) (string, error) {
	for _, config := range severities {
		if config.Label == severity {
			return config.Slack_emoji, nil
		}
	}
	return "", fmt.Errorf("No Slack icon available for severity %s", severity)
}

func GetIconForEcosystem(ecosystem string, ecosystems []EcosystemConfig) (string, error) {
	for _, config := range ecosystems {
		if config.Label == ecosystem {
			return config.Slack_emoji, nil
		}
	}
	return "", fmt.Errorf("No Slack icon available for ecosystem %s", ecosystem)
}

func GetTeamConfigBySlug(teamSlug string, teams []TeamConfig) (TeamConfig, error) {
	for _, team := range teams {
		if team.Github_slug == teamSlug {
			return team, nil
		}
	}
	return TeamConfig{}, fmt.Errorf("No config found for team %s", teamSlug)
}
