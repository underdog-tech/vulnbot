package config

import (
	"fmt"
	"os"
	"reflect"
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
	Github_org            string
	Slack_auth_token      string
	Github_token          string
	Quiet                 bool
	Verbose               int
	Severity              []SeverityConfig
	Ecosystem             []EcosystemConfig
	Team                  []TeamConfig
	Reporters             []string
}

func fileExists(fname string) bool {
	if _, err := os.Stat(fname); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func GetUserConfig(configFile string) (Config, error) {
	log := logger.Get()

	userCfg := Config{}

	// Use reflection to register all config fields in Viper to set up defaults
	cfgFields := reflect.ValueOf(userCfg)
	cfgType := cfgFields.Type()

	for i := 0; i < cfgFields.NumField(); i++ {
		viper.SetDefault(cfgType.Field(i).Name, cfgFields.Field(i).Interface())
	}

	// Load the main config file
	if !fileExists(configFile) {
		log.Fatal().Str("config", configFile).Msg("Config file not found.")
	}
	viper.SetConfigFile(configFile)
	if err := viper.ReadInConfig(); err != nil {
		log.Fatal().Err(err).Msg("Error reading config file.")
	}

	// (Optionally) Load a .env file
	if fileExists("./.env") {
		viper.SetConfigFile("./.env")
		viper.SetConfigType("env")
		if err := viper.ReadInConfig(); err != nil {
			log.Error().Err(err).Msg("Error loading .env file.")
		}
	} else {
		log.Warn().Msg("No .env file found; not loaded.")
	}

	// Set up env var overrides
	replacer := strings.NewReplacer("-", "_")
	viper.SetEnvKeyReplacer(replacer)
	viper.SetEnvPrefix("vulnbot")
	viper.AutomaticEnv()

	// Finally, copy all loaded values into the config object
	_ = viper.Unmarshal(&userCfg)

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
