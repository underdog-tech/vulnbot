package configs

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
	severities := []SeverityConfig{
		{Label: "High", Slack_emoji: ":high:"},
		{Label: "Low", Slack_emoji: ":low:"},
	}
	icon := GetIconForSeverity("High", severities)
	expected := ":high:"
	checkFail(t, icon, expected)
}

func TestGetIconForUnconfiguredSeverity(t *testing.T) {
	severities := []SeverityConfig{
		{Label: "High", Slack_emoji: ":high:"},
		{Label: "Low", Slack_emoji: ":low:"},
	}
	icon := GetIconForSeverity("Medium", severities)
	expected := " "
	checkFail(t, icon, expected)
}

func TestGetIconForConfiguredEcosystem(t *testing.T) {
	ecosystems := []EcosystemConfig{
		{Label: "Pip", Slack_emoji: ":python:"},
		{Label: "Go", Slack_emoji: ":golang:"},
	}
	icon := GetIconForEcosystem("Pip", ecosystems)
	expected := ":python:"
	checkFail(t, icon, expected)
}

func TestGetConfiguredTeamConfigBySlug(t *testing.T) {
	testersTeam := TeamConfig{Name: "Testers", Github_slug: "testers-team"}
	failersTeam := TeamConfig{Name: "Failers", Github_slug: "failers-team"}
	TeamConfigs := []TeamConfig{
		testersTeam,
		failersTeam,
	}
	team := GetTeamConfigBySlug("testers-team", TeamConfigs)
	checkFail(t, team, testersTeam)
}

func TestGetUnconfiguredTeamConfigBySlug(t *testing.T) {
	TeamConfigs := []TeamConfig{} // Empty is easiest for this purpose
	team := GetTeamConfigBySlug("unknown-team", TeamConfigs)
	checkFail(t, team, TeamConfig{})
}
