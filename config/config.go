package config

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/underdog-tech/vulnbot/logger"

	viperClient "github.com/spf13/viper"
)

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

type Config struct {
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

type Viper struct {
	*viperClient.Viper
}

type ViperParams struct {
	ConfigPath  *string
	Output      interface{}
	EnvFileName *string
}

func NewViper() Viper {
	viper := viperClient.New()
	return Viper{viper}
}

func (v *Viper) LoadConfig(params ViperParams) error {
	log := logger.Get()

	filename := filepath.Base(*params.ConfigPath)
	extension := filepath.Ext(*params.ConfigPath)
	configDir := filepath.Dir(*params.ConfigPath)

	v.SetConfigName(filename)
	v.AddConfigPath(configDir)
	v.SetConfigType(strings.TrimLeft(extension, "."))

	err := v.ReadInConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to read config.")
		return err
	}

	err = v.Unmarshal(&params.Output)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to unmarshal config.")
		return err
	}

	log.Debug().Any("config", params.Output).Msg("Config loaded.")
	return nil
}

func (v *Viper) LoadEnv(params ViperParams) error {
	log := logger.Get()

	// Read in environment variables that match
	v.SetConfigFile(*params.EnvFileName)
	v.AutomaticEnv()

	err := v.ReadInConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to read ENV file.")
		return err
	}

	err = v.Unmarshal(&params.Output)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to unmarshal ENV.")
		return err
	}

	log.Debug().Any("env", params.Output).Msg("ENV loaded.")
	return nil
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
