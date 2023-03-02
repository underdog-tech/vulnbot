package main

import (
	"github.com/BurntSushi/toml"
)

type severityConfig struct {
	Label       string
	Slack_emoji string
}

type ecosystemConfig struct {
	Label       string
	Slack_emoji string
}

type teamConfig struct {
	Name          string
	Github_slug   string
	Slack_channel string
	Repositories  []string
}

type tomlConfig struct {
	Default_slack_channel string
	Severity              []severityConfig
	Ecosystem             []ecosystemConfig
	Team                  []teamConfig
}

func loadConfig() tomlConfig {
	var config tomlConfig

	_, err := toml.DecodeFile("config.toml", &config)
	if err != nil {
		panic(err)
	}
	return config
}

func getIconForSeverity(severity string, severities []severityConfig) string {
	for _, config := range severities {
		if config.Label == severity {
			return config.Slack_emoji
		}
	}
	return " "
}

func getIconForEcosystem(ecosystem string, ecosystems []ecosystemConfig) string {
	for _, config := range ecosystems {
		if config.Label == ecosystem {
			return config.Slack_emoji
		}
	}
	return " "
}

func getRepositoryOwner(repoName string, teams []teamConfig) teamConfig {
	for _, team := range teams {
		for _, repo := range team.Repositories {
			if repo == repoName {
				return team
			}
		}
	}
	return teamConfig{}
}

func getTeamConfigByName(teamName string, teams []teamConfig) teamConfig {
	for _, team := range teams {
		if team.Name == teamName {
			return team
		}
	}
	return teamConfig{}
}
