package main

import (
	"reflect"
	"testing"
)

func checkFail(t *testing.T, actual interface{}, expected interface{}) {
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Expected: \"%v\"; Actual: \"%v\"", expected, actual)
	}
}

func TestGetIconForConfiguredSeverity(t *testing.T) {
	severities := []severityConfig{
		{Label: "High", Slack_emoji: ":high:"},
		{Label: "Low", Slack_emoji: ":low:"},
	}
	icon := getIconForSeverity("High", severities)
	expected := ":high:"
	checkFail(t, icon, expected)
}

func TestGetIconForUnconfiguredSeverity(t *testing.T) {
	severities := []severityConfig{
		{Label: "High", Slack_emoji: ":high:"},
		{Label: "Low", Slack_emoji: ":low:"},
	}
	icon := getIconForSeverity("Medium", severities)
	expected := " "
	checkFail(t, icon, expected)
}

func TestGetIconForConfiguredEcosystem(t *testing.T) {
	ecosystems := []ecosystemConfig{
		{Label: "Pip", Slack_emoji: ":python:"},
		{Label: "Go", Slack_emoji: ":golang:"},
	}
	icon := getIconForEcosystem("Pip", ecosystems)
	expected := ":python:"
	checkFail(t, icon, expected)
}

func TestGetConfiguredRepositoryOwner(t *testing.T) {
	testersTeam := teamConfig{Name: "Testers", Repositories: []string{"good-stuff", "broken-stuff"}}
	failersTeam := teamConfig{Name: "Failers", Repositories: []string{"other-stuff"}}
	teamConfigs := []teamConfig{
		testersTeam,
		failersTeam,
	}
	owner := getRepositoryOwner("broken-stuff", teamConfigs)
	checkFail(t, owner, testersTeam)
}

func TestGetUnconfiguredRepositoryOwner(t *testing.T) {
	teamConfigs := []teamConfig{} // Empty is easiest for this purpose
	owner := getRepositoryOwner("unknown", teamConfigs)
	checkFail(t, owner, teamConfig{})
}

func TestGetConfiguredTeamConfigByName(t *testing.T) {
	testersTeam := teamConfig{Name: "Testers", Repositories: []string{"good-stuff", "broken-stuff"}}
	failersTeam := teamConfig{Name: "Failers", Repositories: []string{"other-stuff"}}
	teamConfigs := []teamConfig{
		testersTeam,
		failersTeam,
	}
	team := getTeamConfigByName("Testers", teamConfigs)
	checkFail(t, team, testersTeam)
}

func TestGetUnconfiguredTeamConfigByName(t *testing.T) {
	teamConfigs := []teamConfig{} // Empty is easiest for this purpose
	team := getTeamConfigByName("Unknown", teamConfigs)
	checkFail(t, team, teamConfig{})
}
