package reporting

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/underdog-tech/vulnbot/config"
)

var TEST_REPORT_TIME time.Time = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
var TEST_REPORT_TIME_FORMATTED string = "Thu, 01 Jan 1970 00:00:00 UTC"

type MockSlackClient struct {
	mock.Mock
}

func (m *MockSlackClient) PostMessage(channelID string, options ...slack.MsgOption) (string, string, error) {
	args := m.Called(channelID, options)
	return args.String(0), args.String(1), args.Error(2)
}

func TestSendSlackMessagesSuccess(t *testing.T) {
	mockClient := new(MockSlackClient)
	config := config.Config{}
	reporter := SlackReporter{Config: config, client: mockClient}

	mockClient.On("PostMessage", "channel", mock.Anything, mock.Anything).Return("", "", nil).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	reporter.sendSlackMessage("channel", slack.MsgOptionText("message", false), wg)

	mockClient.AssertExpectations(t)
}

func TestSendSlackMessagesError(t *testing.T) {
	mockClient := new(MockSlackClient)
	config := config.Config{}
	reporter := SlackReporter{Config: config, client: mockClient}

	mockClient.On("PostMessage", "channel", mock.Anything, mock.Anything).Return("", "", fmt.Errorf("Failed to send Slack message")).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	reporter.sendSlackMessage("channel", slack.MsgOptionText("message", false), wg)

	mockClient.AssertExpectations(t)
}

// Test that nothing errors or bombs out. This should perform some assertions at some point.
func TestSendSlackMessageWithNoClient(t *testing.T) {
	config := config.Config{}
	// Create a report instance with NO client
	reporter := SlackReporter{Config: config}

	wg := new(sync.WaitGroup)
	wg.Add(1)
	reporter.sendSlackMessage("channel", slack.MsgOptionText("message", false), wg)
}

func TestIsSlackTokenMissing(t *testing.T) {
	_, err := NewSlackReporter(config.Config{}, "")
	assert.Error(t, err, "No Slack token was provided.")
}

func TestSlackTokenIsNotMissing(t *testing.T) {
	_, err := NewSlackReporter(config.Config{}, "slackToken")
	assert.NoError(t, err)
}

func TestBuildSlackSummaryReport(t *testing.T) {
	reporter := SlackReporter{}

	// Construct a full summary report so that we can verify the output
	report := NewFindingSummary()
	report.AffectedRepos = 2
	report.TotalCount = 42
	report.VulnsByEcosystem[config.FindingEcosystemPython] = 2
	report.VulnsByEcosystem[config.FindingEcosystemJS] = 40
	report.VulnsBySeverity[config.FindingSeverityCritical] = 10
	report.VulnsBySeverity[config.FindingSeverityHigh] = 10
	report.VulnsBySeverity[config.FindingSeverityModerate] = 10
	report.VulnsBySeverity[config.FindingSeverityLow] = 12

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
						"text": TEST_REPORT_TIME_FORMATTED,
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
					"text": "  *Js:* 40",
				},
			},
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": "  *Python:* 2",
				},
			},
		},
	}
	expected, _ := json.Marshal(expected_data)
	summary := reporter.buildSummaryReport("OrgName Vulnbot Report", 13, report, TEST_REPORT_TIME)
	actual, _ := json.Marshal(summary)
	assert.JSONEq(t, string(expected), string(actual))
}

func TestSendSlackSummaryReportSendsSingleMessage(t *testing.T) {
	mockClient := new(MockSlackClient)
	config := config.Config{Default_slack_channel: "channel"}
	reporter := SlackReporter{Config: config, client: mockClient}
	report := NewFindingSummary()

	mockClient.On("PostMessage", "channel", mock.Anything, mock.Anything).Return("", "", nil).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	_ = reporter.SendSummaryReport("Foo", 1, report, TEST_REPORT_TIME, wg)
	wg.Wait()

	mockClient.AssertExpectations(t)
}

func TestBuildSlackTeamRepositoryReport(t *testing.T) {
	reporter := SlackReporter{}

	report := NewProjectFindingSummary("foo")
	report.VulnsByEcosystem[config.FindingEcosystemPython] = 15
	report.VulnsBySeverity[config.FindingSeverityCritical] = 2
	report.VulnsBySeverity[config.FindingSeverityHigh] = 3
	report.VulnsBySeverity[config.FindingSeverityLow] = 10

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
	repoReport := reporter.buildTeamRepositoryReport(&report)
	actual, _ := json.Marshal(repoReport)
	assert.JSONEq(t, string(expected), string(actual))
}

func TestBuildSlackTeamReport(t *testing.T) {
	cfg := config.Config{
		Team: []config.TeamConfig{
			{Name: "TeamName", Slack_channel: "team-foo", Github_slug: "TeamName"},
		},
	}
	reporter := SlackReporter{Config: cfg}

	repo1Report := NewProjectFindingSummary("repo1")
	repo1Report.VulnsByEcosystem[config.FindingEcosystemPython] = 10
	repo1Report.VulnsBySeverity[config.FindingSeverityLow] = 10

	repo2Report := NewProjectFindingSummary("repo2")
	repo2Report.VulnsByEcosystem[config.FindingEcosystemPython] = 5
	repo2Report.VulnsBySeverity[config.FindingSeverityCritical] = 1
	repo2Report.VulnsBySeverity[config.FindingSeverityModerate] = 4

	summaryReport := NewProjectFindingSummary(SUMMARY_KEY)
	summaryReport.AffectedRepos = 2
	summaryReport.TotalCount = 15

	repoReports := TeamProjectCollection{
		&repo1Report, &repo2Report, &summaryReport,
	}

	// `buildTeamRepositoryReport` is tested elsewhere, so no need to manually
	// build up its output here.
	// We have to marshal and then unmarshal to get then into JSON format then
	// back into a Go data structure.
	var repo1Expected, repo2Expected map[string]interface{}
	repo1Data := reporter.buildTeamRepositoryReport(&repo1Report)
	repo2Data := reporter.buildTeamRepositoryReport(&repo2Report)
	repo1ExpectedBytes, _ := json.Marshal(repo1Data)
	_ = json.Unmarshal(repo1ExpectedBytes, &repo1Expected)
	repo2ExpectedBytes, _ := json.Marshal(repo2Data)
	_ = json.Unmarshal(repo2ExpectedBytes, &repo2Expected)

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
						"text": TEST_REPORT_TIME_FORMATTED,
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
			repo2Expected,
			repo1Expected,
		},
	}
	expected, _ := json.Marshal(expectedData)
	teamReport := reporter.buildTeamReport(cfg.Team[0], repoReports, TEST_REPORT_TIME)
	actual, _ := json.Marshal(teamReport.Message)
	// Ensure the Slack Blocks match up
	assert.JSONEq(t, string(expected), string(actual))
	// Ensure it's set for the right channel.
	assert.Equal(t, "team-foo", teamReport.ChannelID)
}

func TestSendSlackTeamReportsSendsMessagePerTeam(t *testing.T) {
	// We want to provide config that contains 2 teams with channels, and one without.
	// There will also be a report create for a team not included in this map.
	teamFoo := config.TeamConfig{Name: "foo", Slack_channel: "team-foo", Github_slug: "foo"}
	teamBar := config.TeamConfig{Name: "bar", Slack_channel: "team-bar", Github_slug: "bar"}

	cfg := config.Config{
		Team: []config.TeamConfig{
			teamFoo,
			teamBar,
			{Name: "baz", Github_slug: "baz"},
		},
	}
	mockClient := new(MockSlackClient)
	reporter := SlackReporter{Config: cfg, client: mockClient}
	repo1Report := NewProjectFindingSummary("repo1")
	repo2Report := NewProjectFindingSummary("repo2")
	summaryReport := NewProjectFindingSummary(SUMMARY_KEY)
	teamReports := map[config.TeamConfig]TeamProjectCollection{
		teamFoo: {
			&repo1Report,
			&repo2Report,
			&summaryReport,
		},
		teamBar: {
			&repo1Report,
			&summaryReport,
		},
	}
	mockClient.On("PostMessage", "team-foo", mock.Anything, mock.Anything).Return("", "", nil).Once()
	mockClient.On("PostMessage", "team-bar", mock.Anything, mock.Anything).Return("", "", nil).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	_ = reporter.SendTeamReports(teamReports, TEST_REPORT_TIME, wg)
	wg.Wait()

	mockClient.AssertExpectations(t)
}
