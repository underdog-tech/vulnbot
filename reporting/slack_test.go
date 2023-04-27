package reporting

import (
	"fmt"
	"sync"
	"testing"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/underdog-tech/vulnbot/config"
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
	reporter := SlackReporter{config: config, client: mockClient}

	mockClient.On("PostMessage", "channel", mock.Anything, mock.Anything).Return("", "", nil).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	reporter.sendSlackMessage("channel", "message", wg)

	mockClient.AssertExpectations(t)
}

func TestSendSlackMessagesError(t *testing.T) {
	mockClient := new(MockSlackClient)
	config := config.TomlConfig{}
	reporter := SlackReporter{config: config, client: mockClient}

	mockClient.On("PostMessage", "channel", mock.Anything, mock.Anything).Return("", "", fmt.Errorf("Failed to send Slack message")).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	reporter.sendSlackMessage("channel", "message", wg)

	mockClient.AssertExpectations(t)
}

// Test that nothing errors or bombs out. This should perform some assertions at some point.
func TestSendSlackMessageWithNoClient(t *testing.T) {
	config := config.TomlConfig{}
	// Create a report instance with NO client
	reporter := SlackReporter{config: config}

	wg := new(sync.WaitGroup)
	wg.Add(1)
	reporter.sendSlackMessage("channel", "message", wg)
}

func TestIsSlackTokenMissing(t *testing.T) {
	_, err := NewSlackReporter(config.TomlConfig{}, "")
	assert.Error(t, err, "No Slack token was provided.")
}

func TestSlackTokenIsNotMissing(t *testing.T) {
	_, err := NewSlackReporter(config.TomlConfig{}, "slackToken")
	assert.NoError(t, err)
}

func TestBuildSummaryReport(t *testing.T) {
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
	expected := `*OrgName Dependabot Report for now*
Total repositories: 13
Total vulnerabilities: 42
Affected repositories: 2

*Breakdown by Severity*
  Critical: 10
  High: 10
  Moderate: 10
  Low: 12

*Breakdown by Ecosystem*
  Go: 0
  Npm: 40
  Pip: 2
  Rubygems: 0
`

	actual := reporter.buildSummaryReport("OrgName Dependabot Report for now", 13, report)
	assert.Equal(t, expected, actual)
}

func TestSendSummaryReportSendsSingleMessage(t *testing.T) {
	mockClient := new(MockSlackClient)
	config := config.TomlConfig{Default_slack_channel: "channel"}
	reporter := SlackReporter{config: config, client: mockClient}
	report := NewVulnerabilityReport()

	mockClient.On("PostMessage", "channel", mock.Anything, mock.Anything).Return("", "", nil).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	reporter.SendSummaryReport("Foo", 1, report, wg)
	wg.Wait()

	mockClient.AssertExpectations(t)
}

// This test is very long because it is attempting to verify we are generating
// the proper message for multiple teams, which requires both a lot of input, as
// well as a lot of output.
func TestBuildTeamReports(t *testing.T) {
	// We want to provide config that contains 2 teams with channels, and one without.
	// There will also be a report create for a team not included in this map.
	config := config.TomlConfig{
		Team: []config.TeamConfig{
			{Name: "foo", Slack_channel: "team-foo", Github_slug: "foo"},
			{Name: "bar", Slack_channel: "team-bar", Github_slug: "bar"},
			{Name: "baz", Github_slug: "baz"},
		},
	}
	reporter := SlackReporter{config: config}

	repo1Report := NewVulnerabilityReport()
	repo1Report.VulnsByEcosystem["Pip"] = 10
	repo1Report.VulnsBySeverity["Low"] = 10

	repo2Report := NewVulnerabilityReport()
	repo2Report.VulnsByEcosystem["Pip"] = 5
	repo2Report.VulnsBySeverity["Critical"] = 1
	repo2Report.VulnsBySeverity["Moderate"] = 4

	fooSummary := NewVulnerabilityReport()
	fooSummary.AffectedRepos = 2
	fooSummary.TotalCount = 15

	barSummary := NewVulnerabilityReport()
	barSummary.AffectedRepos = 1
	barSummary.TotalCount = 10
	teamReports := map[string]map[string]VulnerabilityReport{
		"foo": {
			"repo1":     repo1Report,
			"repo2":     repo2Report,
			SUMMARY_KEY: fooSummary,
		},
		"bar": {
			"repo1":     repo1Report,
			SUMMARY_KEY: barSummary,
		},
		"baz": {
			"repo2": repo2Report,
		},
		"blah": {
			"repo1": repo1Report,
			"repo2": repo2Report,
		},
	}
	expected := map[string]string{
		"team-foo": `*foo Dependabot Report for now*
Affected repositories: 2
Total vulnerabilities: 15
*repo1* --   *Critical*: 0   *High*: 0   *Moderate*: 0   *Low*: 10 
*repo2* --   *Critical*: 1   *High*: 0   *Moderate*: 4   *Low*: 0 
`,
		"team-bar": `*bar Dependabot Report for now*
Affected repositories: 1
Total vulnerabilities: 10
*repo1* --   *Critical*: 0   *High*: 0   *Moderate*: 0   *Low*: 10 
`,
	}
	actual := reporter.buildTeamReports(teamReports, "now")
	assert.Equal(t, expected, actual)
}

func TestSendTeamReportsSendsMessagePerTeam(t *testing.T) {
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
	reporter := SlackReporter{config: config, client: mockClient}
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
	reporter.SendTeamReports(teamReports, wg)
	wg.Wait()

	mockClient.AssertExpectations(t)
}
