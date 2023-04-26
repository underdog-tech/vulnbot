package reporting

import (
	"fmt"
	"sync"
	"time"

	"github.com/underdog-tech/vulnbot/config"
	"github.com/underdog-tech/vulnbot/logger"

	"github.com/slack-go/slack"
)

type SlackReporter struct {
	slackToken string
	config     config.TomlConfig
	client     SlackClientInterface
}

type SlackClientInterface interface {
	PostMessage(channelID string, options ...slack.MsgOption) (string, string, error)
}

func NewSlackClient(slackToken string) (SlackClientInterface, error) {
	if slackToken == "" {
		return nil, fmt.Errorf("No Slack token was provided.")
	}
	return slack.New(slackToken, slack.OptionDebug(true)), nil
}

func (s *SlackReporter) SendSummaryReport(
	header string,
	numRepos int,
	report VulnerabilityReport,
	wg *sync.WaitGroup,
) error {
	defer wg.Done()

	summaryReport := fmt.Sprintf(
		"*%s*\n"+
			"Total repositories: %d\n"+
			"Total vulnerabilities: %d\n"+
			"Affected repositories: %d\n",
		header,
		numRepos,
		report.TotalCount,
		report.AffectedRepos,
	)

	severityReport := "*Breakdown by Severity*\n"
	for severity, vulnCount := range report.VulnsBySeverity {
		icon, err := config.GetIconForSeverity(severity, s.config.Severity)
		if err != nil {
			icon = DEFAULT_SLACK_ICON
		}
		severityReport = fmt.Sprintf("%s%s %s: %d\n", severityReport, icon, severity, vulnCount)
	}

	ecosystemReport := "*Breakdown by Ecosystem*\n"
	for ecosystem, vulnCount := range report.VulnsByEcosystem {
		icon, err := config.GetIconForEcosystem(ecosystem, s.config.Ecosystem)
		if err != nil {
			icon = DEFAULT_SLACK_ICON
		}
		ecosystemReport = fmt.Sprintf("%s%s %s: %d\n", ecosystemReport, icon, ecosystem, vulnCount)
	}
	summaryReport = fmt.Sprintf("%s\n%s\n%s", summaryReport, severityReport, ecosystemReport)
	wg.Add(1)
	s.sendSlackMessage(s.config.Default_slack_channel, summaryReport, wg)
	return nil
}

func (s *SlackReporter) SendTeamReports(
	teamReports map[string]map[string]VulnerabilityReport,
	wg *sync.WaitGroup,
) error {
	defer wg.Done()
	log := logger.Get()
	reportTime := s.GetReportTime()
	for team, repos := range teamReports {
		teamReport := ""
		teamInfo, err := config.GetTeamConfigBySlug(team, s.config.Team)
		if err != nil {
			log.Warn().Str("team", team).Msg("Skipping report for unconfigured team.")
			continue
		}
		for name, repo := range repos {
			if name == SUMMARY_KEY {
				continue
			}
			repoReport := fmt.Sprintf("*%s* -- ", name)
			for severity, count := range repo.VulnsBySeverity {
				icon, err := config.GetIconForSeverity(severity, s.config.Severity)
				if err != nil {
					icon = DEFAULT_SLACK_ICON
				}
				repoReport += fmt.Sprintf("*%s %s*: %d ", icon, severity, count)
			}
			repoReport += "\n"
			teamReport += repoReport
		}
		teamSummary := repos[SUMMARY_KEY]
		teamSummaryReport := fmt.Sprintf(
			"*%s Dependabot Report for %s*\n"+
				"Affected repositories: %d\n"+
				"Total vulnerabilities: %d\n",
			teamInfo.Name,
			reportTime,
			teamSummary.AffectedRepos, // Subtract the summary report
			teamSummary.TotalCount,
		)
		teamReport = teamSummaryReport + teamReport + "\n"
		if teamInfo.Slack_channel != "" {
			wg.Add(1)
			go s.sendSlackMessage(teamInfo.Slack_channel, teamReport, wg)
		} else {
			log.Debug().Str("team", team).Str("teamReport", teamReport).Msg("Discarding team report because no Slack channel configured.")
		}
	}
	return nil
}

func (s *SlackReporter) sendSlackMessage(channel string, message string, wg *sync.WaitGroup) {
	defer wg.Done()
	log := logger.Get()
	if s.client != nil {
		_, timestamp, err := s.client.PostMessage(channel, slack.MsgOptionText(message, false), slack.MsgOptionAsUser(true))
		if err != nil {
			log.Error().Err(err).Msg("Failed to send Slack message.")
		} else {
			log.Info().Str("channel", channel).Str("timestamp", timestamp).Msg("Message sent to Slack.")
		}
	} else {
		log.Warn().Str("message", message).Str("channel", channel).Msg("No Slack client available. Message not sent.")
	}
}

func (s *SlackReporter) GetReportTime() string {
	return time.Now().Format(time.RFC1123)
}

func NewSlackReporter(config config.TomlConfig, slackToken string) SlackReporter {
	log := logger.Get()
	client, err := NewSlackClient(slackToken)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to create Slack client.")
	}
	return SlackReporter{config: config, client: client}
}
