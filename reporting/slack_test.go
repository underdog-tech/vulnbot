package reporting

import (
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"testing"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/underdog-tech/vulnbot/config"
)

const (
	UNIX_TIME = 1672534800
)

type MockSlackClient struct {
	mock.Mock
}

func (m *MockSlackClient) PostMessage(channelID string, options ...slack.MsgOption) (string, string, error) {
	args := m.Called(channelID, options)
	return args.String(0), args.String(1), args.Error(2)
}

func TestSendSlackMessagesSuccess(t *testing.T) {
	mockClient := new(MockSlackClient)
	config := config.TomlConfig{}
	reporter := SlackReporter{Config: config, client: mockClient}

	mockClient.On("PostMessage", "channel", mock.Anything, mock.Anything).Return("", "", nil).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	reporter.sendSlackMessage("channel", slack.MsgOptionText("message", false), wg)

	mockClient.AssertExpectations(t)
}

func TestSendSlackMessagesError(t *testing.T) {
	mockClient := new(MockSlackClient)
	config := config.TomlConfig{}
	reporter := SlackReporter{Config: config, client: mockClient}

	mockClient.On("PostMessage", "channel", mock.Anything, mock.Anything).Return("", "", fmt.Errorf("Failed to send Slack message")).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	reporter.sendSlackMessage("channel", slack.MsgOptionText("message", false), wg)

	mockClient.AssertExpectations(t)
}

// Test that nothing errors or bombs out. This should perform some assertions at some point.
func TestSendSlackMessageWithNoClient(t *testing.T) {
	config := config.TomlConfig{}
	// Create a report instance with NO client
	reporter := SlackReporter{Config: config}

	wg := new(sync.WaitGroup)
	wg.Add(1)
	reporter.sendSlackMessage("channel", slack.MsgOptionText("message", false), wg)
}

func TestIsSlackTokenMissing(t *testing.T) {
	_, err := NewSlackReporter(config.TomlConfig{}, "")
	assert.Error(t, err, "No Slack token was provided.")
}

func TestSlackTokenIsNotMissing(t *testing.T) {
	_, err := NewSlackReporter(config.TomlConfig{}, "slackToken")
	assert.NoError(t, err)
}

func TestBuildSlackSummaryReport(t *testing.T) {
	reporter := SlackReporter{}

	// Construct a full summary report so that we can verify the output
	report := NewVulnerabilityReport()
	report.AffectedRepos = 2
	report.TotalCount = 42
	report.VulnsByEcosystem["Pip"] = 2
	report.VulnsByEcosystem["Npm"] = 40
	report.VulnsBySeverity["Critical"] = 10
	report.VulnsBySeverity["High"] = 10
	report.VulnsBySeverity["Moderate"] = 10
	report.VulnsBySeverity["Low"] = 12

	expected_data := map[string]interface{}{
		"replace_original": false,
		"delete_original":  false,
		"metadata": map[string]interface{}{
			"event_payload": nil,
			"event_type":    "",
		},
		"blocks": []map[string]interface{}{
			{
				"type": "header",
				"text": map[string]interface{}{
					"type": "plain_text",
					"text": "OrgName Vulnbot Report",
				},
			},
			{
				"type": "divider",
			},
			{
				"type": "context",
				"elements": []map[string]interface{}{
					{
						"type": "plain_text",
						"text": strconv.Itoa(int(UNIX_TIME)),
					},
				},
			},
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": "*Total repositories:* 13\n*Total vulnerabilities:* 42\n*Affected repositories:* 2\n",
				},
			},
			{
				"type": "header",
				"text": map[string]interface{}{
					"type": "plain_text",
					"text": "Breakdown by Severity",
				},
			},
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": "  *Critical:* 10",
				},
			},
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": "  *High:* 10",
				},
			},
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": "  *Moderate:* 10",
				},
			},
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": "  *Low:* 12",
				},
			},
			{
				"type": "header",
				"text": map[string]interface{}{
					"type": "plain_text",
					"text": "Breakdown by Ecosystem",
				},
			},
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": "  *Npm:* 40",
				},
			},
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": "  *Pip:* 2",
				},
			},
		},
	}
	expected, _ := json.Marshal(expected_data)
	summary := reporter.buildSummaryReport("OrgName Vulnbot Report", 13, report, UNIX_TIME)
	actual, _ := json.Marshal(summary)
	assert.JSONEq(t, string(expected), string(actual))
}

func TestSendSlackSummaryReportSendsSingleMessage(t *testing.T) {
	mockClient := new(MockSlackClient)
	config := config.TomlConfig{Default_slack_channel: "channel"}
	reporter := SlackReporter{Config: config, client: mockClient}
	report := NewVulnerabilityReport()

	mockClient.On("PostMessage", "channel", mock.Anything, mock.Anything).Return("", "", nil).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	reporter.SendSummaryReport("Foo", 1, report, UNIX_TIME, wg)
	wg.Wait()

	mockClient.AssertExpectations(t)
}

func TestBuildSlackTeamRepositoryReport(t *testing.T) {
	reporter := SlackReporter{}

	report := NewVulnerabilityReport()
	report.VulnsByEcosystem["Pip"] = 15
	report.VulnsBySeverity["Critical"] = 2
	report.VulnsBySeverity["High"] = 3
	report.VulnsBySeverity["Low"] = 10

	expected_data := map[string]interface{}{
		"type": "section",
		"fields": []map[string]interface{}{
			{
				"type": "mrkdwn",
				"text": "  *foo*",
			},
			{
				"type": "mrkdwn",
				"text": " 2 Critical |  3 High |  0 Moderate | 10 Low",
			},
		},
	}

	expected, _ := json.Marshal(expected_data)
	repoReport := reporter.buildTeamRepositoryReport("foo", report)
	actual, _ := json.Marshal(repoReport)
	assert.JSONEq(t, string(expected), string(actual))
}

func TestBuildSlackTeamReport(t *testing.T) {
	config := config.TomlConfig{
		Team: []config.TeamConfig{
			{Name: "TeamName", Slack_channel: "team-foo", Github_slug: "TeamName"},
		},
	}
	reporter := SlackReporter{Config: config}

	repo1Report := NewVulnerabilityReport()
	repo1Report.VulnsByEcosystem["Pip"] = 10
	repo1Report.VulnsBySeverity["Low"] = 10

	repo2Report := NewVulnerabilityReport()
	repo2Report.VulnsByEcosystem["Pip"] = 5
	repo2Report.VulnsBySeverity["Critical"] = 1
	repo2Report.VulnsBySeverity["Moderate"] = 4

	summaryReport := NewVulnerabilityReport()
	summaryReport.AffectedRepos = 2
	summaryReport.TotalCount = 15

	repoReports := map[string]VulnerabilityReport{
		"repo1":     repo1Report,
		"repo2":     repo2Report,
		SUMMARY_KEY: summaryReport,
	}

	// `buildTeamRepositoryReport` is tested elsewhere, so no need to manually
	// build up its output here.
	// We have to marshal and then unmarshal to get then into JSON format then
	// back into a Go data structure.
	var repo1Expected, repo2Expected map[string]interface{}
	repo1Data := reporter.buildTeamRepositoryReport("repo1", repo1Report)
	repo2Data := reporter.buildTeamRepositoryReport("repo2", repo2Report)
	repo1ExpectedBytes, _ := json.Marshal(repo1Data)
	json.Unmarshal(repo1ExpectedBytes, &repo1Expected)
	repo2ExpectedBytes, _ := json.Marshal(repo2Data)
	json.Unmarshal(repo2ExpectedBytes, &repo2Expected)

	expectedData := map[string]interface{}{
		"replace_original": false,
		"delete_original":  false,
		"metadata": map[string]interface{}{
			"event_payload": nil,
			"event_type":    "",
		},
		"blocks": []map[string]interface{}{
			{
				"type": "header",
				"text": map[string]interface{}{
					"type": "plain_text",
					"text": "TeamName Vulnbot Report",
				},
			},
			{
				"type": "divider",
			},
			{
				"type": "context",
				"elements": []map[string]interface{}{
					{
						"type": "plain_text",
						"text": "now",
					},
				},
			},
			{
				"type": "section",
				"fields": []map[string]interface{}{
					{
						"type": "mrkdwn",
						"text": "*  15 Total Vulnerabilities*",
					},
				},
			},
			{
				"type": "divider",
			},
			repo1Expected,
			repo2Expected,
		},
	}
	expected, _ := json.Marshal(expectedData)
	teamReport := reporter.buildTeamReport("TeamName", repoReports, UNIX_TIME)
	actual, _ := json.Marshal(teamReport.Message)
	// Ensure the Slack Blocks match up
	assert.JSONEq(t, string(expected), string(actual))
	// Ensure it's set for the right channel.
	assert.Equal(t, "team-foo", teamReport.ChannelID)
}

func TestSendSlackTeamReportsSendsMessagePerTeam(t *testing.T) {
	// We want to provide config that contains 2 teams with channels, and one without.
	// There will also be a report create for a team not included in this map.
	config := config.TomlConfig{
		Team: []config.TeamConfig{
			{Name: "foo", Slack_channel: "team-foo", Github_slug: "foo"},
			{Name: "bar", Slack_channel: "team-bar", Github_slug: "bar"},
			{Name: "baz", Github_slug: "baz"},
		},
	}
	mockClient := new(MockSlackClient)
	reporter := SlackReporter{Config: config, client: mockClient}
	repo1Report := NewVulnerabilityReport()
	repo2Report := NewVulnerabilityReport()
	teamReports := map[string]map[string]VulnerabilityReport{
		"foo": {
			"repo1": repo1Report,
			"repo2": repo2Report,
		},
		"bar": {
			"repo1": repo1Report,
		},
	}
	mockClient.On("PostMessage", "team-foo", mock.Anything, mock.Anything).Return("", "", nil).Once()
	mockClient.On("PostMessage", "team-bar", mock.Anything, mock.Anything).Return("", "", nil).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	reporter.SendTeamReports(teamReports, UNIX_TIME, wg)
	wg.Wait()

	mockClient.AssertExpectations(t)
}
