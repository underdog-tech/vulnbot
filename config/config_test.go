package config

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
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
	checkFail(t, team, TeamConfig{})
}
