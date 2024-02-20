package reporting_test

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/underdog-tech/vulnbot/configs"
	"github.com/underdog-tech/vulnbot/querying"
	"github.com/underdog-tech/vulnbot/reporting"
	"github.com/underdog-tech/vulnbot/test"
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
	config := configs.Config{}
	reporter := reporting.SlackReporter{Config: &config, Client: mockClient}

	mockClient.On("PostMessage", "channel", mock.Anything, mock.Anything).Return("", "", nil).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	reporter.SendSlackMessage("channel", slack.MsgOptionText("message", false), wg)

	mockClient.AssertExpectations(t)
}

func TestSendSlackMessagesError(t *testing.T) {
	mockClient := new(MockSlackClient)
	config := configs.Config{}
	reporter := reporting.SlackReporter{Config: &config, Client: mockClient}

	mockClient.On("PostMessage", "channel", mock.Anything, mock.Anything).Return("", "", fmt.Errorf("Failed to send Slack message")).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	reporter.SendSlackMessage("channel", slack.MsgOptionText("message", false), wg)

	mockClient.AssertExpectations(t)
}

// Test that nothing errors or bombs out. This should perform some assertions at some point.
func TestSendSlackMessageWithNoClient(t *testing.T) {
	config := configs.Config{}
	// Create a report instance with NO client
	reporter := reporting.SlackReporter{Config: &config}

	wg := new(sync.WaitGroup)
	wg.Add(1)
	reporter.SendSlackMessage("channel", slack.MsgOptionText("message", false), wg)
}

func TestIsSlackTokenMissing(t *testing.T) {
	_, err := reporting.NewSlackReporter(&configs.Config{})
	assert.Error(t, err, "No Slack token was provided.")
}

func TestSlackTokenIsNotMissing(t *testing.T) {
	_, err := reporting.NewSlackReporter(&configs.Config{Slack_auth_token: "slackToken"})
	assert.NoError(t, err)
}

func TestBuildSlackSummaryReport(t *testing.T) {
	reporter := reporting.SlackReporter{Config: &configs.Config{}}

	// Construct a full summary report so that we can verify the output
	report := reporting.NewFindingSummary()
	report.AffectedRepos = 2
	report.TotalCount = 42
	report.VulnsByEcosystem[configs.FindingEcosystemPython] = 2
	report.VulnsByEcosystem[configs.FindingEcosystemJS] = 40
	report.VulnsBySeverity[configs.FindingSeverityCritical] = 10
	report.VulnsBySeverity[configs.FindingSeverityHigh] = 10
	report.VulnsBySeverity[configs.FindingSeverityModerate] = 10
	report.VulnsBySeverity[configs.FindingSeverityLow] = 12

	expected_data := map[string]interface{}{
		"replace_original": false,
		"delete_original":  false,
		"metadata": map[string]interface{}{
			"event_type":    "",
			"event_payload": nil,
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
				"type": "context",
				"elements": []map[string]interface{}{
					{
						"type": "plain_text",
						"text": test.TEST_REPORT_TIME_FORMATTED,
					},
				},
			},
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": "*Total Vulnerabilities:* 42\n*Affected Repositories:* 2\n*Total Repositories:* 13\n",
				},
			},
			{
				"type": "header",
				"text": map[string]interface{}{
					"type": "plain_text",
					"text": "Team Breakdown",
				},
			},
			{
				"type": "divider",
			},
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": ":first_place_medal: *Team Foo:* 0 vulnerabilities",
				},
				"accessory": map[string]interface{}{
					"type": "overflow",
					"options": []map[string]interface{}{
						{
							"text": map[string]interface{}{
								"type":  "plain_text",
								"text":  "  0 Critical",
								"emoji": true,
							},
							"value": "value",
						},
						{
							"text": map[string]interface{}{
								"type":  "plain_text",
								"text":  "  0 High",
								"emoji": true,
							},
							"value": "value",
						},
						{
							"text": map[string]interface{}{
								"type":  "plain_text",
								"text":  "  0 Moderate",
								"emoji": true,
							},
							"value": "value",
						},
						{
							"text": map[string]interface{}{
								"type":  "plain_text",
								"text":  "  0 Low",
								"emoji": true,
							},
							"value": "value",
						},
					},
				},
			},
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": ":second_place_medal: *Team Bar:* 10 vulnerabilities",
				},
				"accessory": map[string]interface{}{
					"type": "overflow",
					"options": []map[string]interface{}{
						{
							"text": map[string]interface{}{
								"type":  "plain_text",
								"text":  "  1 Critical",
								"emoji": true,
							},
							"value": "value",
						},
						{
							"text": map[string]interface{}{
								"type":  "plain_text",
								"text":  "  2 High",
								"emoji": true,
							},
							"value": "value",
						},
						{
							"text": map[string]interface{}{
								"type":  "plain_text",
								"text":  "  3 Moderate",
								"emoji": true,
							},
							"value": "value",
						},
						{
							"text": map[string]interface{}{
								"type":  "plain_text",
								"text":  "  4 Low",
								"emoji": true,
							},
							"value": "value",
						},
					},
				},
			},
			{
				"type": "header",
				"text": map[string]interface{}{
					"type": "plain_text",
					"text": "Severity Breakdown",
				},
			},
			{
				"type": "divider",
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
					"text": "Ecosystem Breakdown",
				},
			},
			{
				"type": "divider",
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
	summary := reporter.BuildSummaryReport("OrgName Vulnbot Report", 13, report, test.TEST_REPORT_TIME, test.TEST_TEAM_SUMMARIES)
	actual, _ := json.Marshal(summary)
	assert.JSONEq(t, string(expected), string(actual))
}

func TestSendSlackSummaryReportSendsSingleMessage(t *testing.T) {
	mockClient := new(MockSlackClient)
	config := configs.Config{Default_slack_channel: "channel"}
	reporter := reporting.SlackReporter{Config: &config, Client: mockClient}
	report := reporting.NewFindingSummary()

	mockClient.On("PostMessage", "channel", mock.Anything, mock.Anything).Return("", "", nil).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	_ = reporter.SendSummaryReport("Foo", 1, report, test.TEST_REPORT_TIME, test.TEST_TEAM_SUMMARIES, wg)
	wg.Wait()

	mockClient.AssertExpectations(t)
}

func TestBuildSlackTeamRepositoryReport(t *testing.T) {
	reporter := reporting.SlackReporter{Config: &configs.Config{}}
	proj := querying.NewProject("foo")
	proj.Links = map[string]string{
		"GitHub": "https://github.com/bar/foo",
	}
	report := reporting.NewProjectFindingSummary(proj)
	report.VulnsByEcosystem[configs.FindingEcosystemPython] = 15
	report.VulnsBySeverity[configs.FindingSeverityCritical] = 2
	report.VulnsBySeverity[configs.FindingSeverityHigh] = 3
	report.VulnsBySeverity[configs.FindingSeverityLow] = 10

	expected_data := map[string]interface{}{
		"type": "section",
		"fields": []map[string]interface{}{
			{
				"type": "mrkdwn",
				"text": "  *foo* · [<https://github.com/bar/foo|GitHub>]",
			},
			{
				"type": "mrkdwn",
				"text": " 2 Critical |  3 High |  0 Moderate | 10 Low",
			},
		},
	}

	expected, _ := json.Marshal(expected_data)
	repoReport := reporter.BuildTeamRepositoryReport(&report)
	actual, _ := json.Marshal(repoReport)
	assert.JSONEq(t, string(expected), string(actual))
}

func TestBuildSlackTeamReport(t *testing.T) {
	cfg := configs.Config{
		Team: []configs.TeamConfig{
			{Name: "TeamName", Slack_channel: "team-foo", Github_slug: "TeamName"},
		},
	}
	reporter := reporting.SlackReporter{Config: &cfg}

	repo1Report := reporting.NewProjectFindingSummary(querying.NewProject("repo1"))
	repo1Report.VulnsByEcosystem[configs.FindingEcosystemPython] = 10
	repo1Report.VulnsBySeverity[configs.FindingSeverityLow] = 10

	repo2Report := reporting.NewProjectFindingSummary(querying.NewProject("repo2"))
	repo2Report.VulnsByEcosystem[configs.FindingEcosystemPython] = 5
	repo2Report.VulnsBySeverity[configs.FindingSeverityCritical] = 1
	repo2Report.VulnsBySeverity[configs.FindingSeverityModerate] = 4

	summaryReport := reporting.NewProjectFindingSummary(querying.NewProject(reporting.SUMMARY_KEY))
	summaryReport.AffectedRepos = 2
	summaryReport.TotalCount = 15

	repoReports := reporting.TeamProjectCollection{
		&repo1Report, &repo2Report, &summaryReport,
	}

	// `buildTeamRepositoryReport` is tested elsewhere, so no need to manually
	// build up its output here.
	// We have to marshal and then unmarshal to get then into JSON format then
	// back into a Go data structure.
	var repo1Expected, repo2Expected map[string]interface{}
	repo1Data := reporter.BuildTeamRepositoryReport(&repo1Report)
	repo2Data := reporter.BuildTeamRepositoryReport(&repo2Report)
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
						"text": test.TEST_REPORT_TIME_FORMATTED,
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
	teamReport := reporter.BuildTeamReport(cfg.Team[0], repoReports, test.TEST_REPORT_TIME)
	actual, _ := json.Marshal(teamReport.Message)
	// Ensure the Slack Blocks match up
	assert.JSONEq(t, string(expected), string(actual))
	// Ensure it's set for the right channel.
	assert.Equal(t, "team-foo", teamReport.ChannelID)
}

func TestSendSlackTeamReportsSendsMessagePerTeam(t *testing.T) {
	// We want to provide config that contains 2 teams with channels, and one without.
	// There will also be a report create for a team not included in this map.
	teamFoo := configs.TeamConfig{Name: "foo", Slack_channel: "team-foo", Github_slug: "foo"}
	teamBar := configs.TeamConfig{Name: "bar", Slack_channel: "team-bar", Github_slug: "bar"}

	cfg := configs.Config{
		Team: []configs.TeamConfig{
			teamFoo,
			teamBar,
			{Name: "baz", Github_slug: "baz"},
		},
	}
	mockClient := new(MockSlackClient)
	reporter := reporting.SlackReporter{Config: &cfg, Client: mockClient}
	repo1Report := reporting.NewProjectFindingSummary(querying.NewProject("repo1"))
	repo2Report := reporting.NewProjectFindingSummary(querying.NewProject("repo2"))
	summaryReport := reporting.NewProjectFindingSummary(querying.NewProject(reporting.SUMMARY_KEY))
	teamReports := map[configs.TeamConfig]reporting.TeamProjectCollection{
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
	_ = reporter.SendTeamReports(teamReports, test.TEST_REPORT_TIME, wg)
	wg.Wait()

	mockClient.AssertExpectations(t)
}

func TestGetVulnerabilityWord(t *testing.T) {
	tests := []struct {
		count    int
		expected string
	}{
		{count: 0, expected: "vulnerability"},
		{count: 1, expected: "vulnerability"},
		{count: 2, expected: "vulnerabilities"},
		{count: 100, expected: "vulnerabilities"},
	}

	for _, test := range tests {
		result := reporting.GetVulnerabilityWord(test.count)
		if result != test.expected {
			t.Errorf("For count %d, got: %s, want: %s", test.count, result, test.expected)
		}
	}
}
