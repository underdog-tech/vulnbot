package config

import (
	"fmt"
	"strings"

	"github.com/underdog-tech/vulnbot/logger"

	"github.com/spf13/viper"
)

type TeamConfig struct {
	Name          string
	Github_slug   string
	Slack_channel string
}

type Config struct {
	Default_slack_channel string
	Disable_slack         bool
	Github_org            string
	Slack_auth_token      string
	Github_token          string
	Quiet                 bool
	Verbose               int
	Severity              []SeverityConfig
	Ecosystem             []EcosystemConfig
	Team                  []TeamConfig
}

type Env struct {
	GithubOrg      string `mapstructure:"GITHUB_ORG"`
	SlackAuthToken string `mapstructure:"SLACK_AUTH_TOKEN"`
	GithubToken    string `mapstructure:"GITHUB_TOKEN"`
}

var viperClient *viper.Viper

type ViperParams struct {
	ConfigPath  *string
	Output      interface{}
	EnvFileName *string
}

func getViper() *viper.Viper {
	if viperClient == nil {
		viperClient = viper.New()
	}
	return viperClient
}

func GetUserConfig(configFile string) (Config, error) {
	log := logger.Get()

	userCfg := Config{}

	// Set up env var overrides
	replacer := strings.NewReplacer("-", "_")
	viper.SetEnvKeyReplacer(replacer)
	viper.SetEnvPrefix("vulnbot")
	viper.AutomaticEnv()

	// Load the main config file
	viper.SetConfigFile(configFile)
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Fatal().Str("config", configFile).Err(err).Msg("Config file not found.")
		} else {
			log.Fatal().Err(err).Msg("Error reading config file.")
		}
	}
	viper.Unmarshal(&userCfg)

	// (Optionally) Load a .env file
	viper.SetConfigFile("./.env")
	viper.SetConfigType("env")
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Warn().Msg("No .env file found; not loaded.")
		} else {
			log.Error().Err(err).Msg("Error loading .env file.")
		}
	}
	viper.Unmarshal(&userCfg)

	return userCfg, nil
}

func GetIconForSeverity(severity FindingSeverityType, severities []SeverityConfig) (string, error) {
	for _, config := range severities {
		if config.Label == SeverityNames[severity] {
			return config.Slack_emoji, nil
		}
	}
	return "", fmt.Errorf("No Slack icon available for severity %s", SeverityNames[severity])
}

func GetIconForEcosystem(ecosystem FindingEcosystemType, ecosystems []EcosystemConfig) (string, error) {
	for _, config := range ecosystems {
		if strings.ToLower(config.Label) == string(ecosystem) {
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
