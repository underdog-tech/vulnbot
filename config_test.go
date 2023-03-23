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

func TestGetConfiguredTeamConfigBySlug(t *testing.T) {
	testersTeam := teamConfig{Name: "Testers", Github_slug: "testers-team"}
	failersTeam := teamConfig{Name: "Failers", Github_slug: "failers-team"}
	teamConfigs := []teamConfig{
		testersTeam,
		failersTeam,
	}
	team := getTeamConfigBySlug("testers-team", teamConfigs)
	checkFail(t, team, testersTeam)
}

func TestGetUnconfiguredTeamConfigBySlug(t *testing.T) {
	teamConfigs := []teamConfig{} // Empty is easiest for this purpose
	team := getTeamConfigBySlug("unknown-team", teamConfigs)
	checkFail(t, team, teamConfig{})
}
