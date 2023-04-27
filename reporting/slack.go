package reporting

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/underdog-tech/vulnbot/config"
	"github.com/underdog-tech/vulnbot/logger"
	"golang.org/x/exp/maps"

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

func (s *SlackReporter) buildSummaryReport(
	header string,
	numRepos int,
	report VulnerabilityReport,
) string {
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
	severities := getSeverityReportOrder()
	for _, severity := range severities {
		vulnCount, _ := report.VulnsBySeverity[severity]
		icon, err := config.GetIconForSeverity(severity, s.config.Severity)
		if err != nil {
			icon = DEFAULT_SLACK_ICON
		}
		severityReport = fmt.Sprintf("%s%s %s: %d\n", severityReport, icon, severity, vulnCount)
	}

	ecosystemReport := "*Breakdown by Ecosystem*\n"
	ecosystems := getEcosystemReportOrder()
	for _, ecosystem := range ecosystems {
		vulnCount, _ := report.VulnsByEcosystem[ecosystem]
		icon, err := config.GetIconForEcosystem(ecosystem, s.config.Ecosystem)
		if err != nil {
			icon = DEFAULT_SLACK_ICON
		}
		ecosystemReport = fmt.Sprintf("%s%s %s: %d\n", ecosystemReport, icon, ecosystem, vulnCount)
	}
	summaryReport = fmt.Sprintf("%s\n%s\n%s", summaryReport, severityReport, ecosystemReport)
	return summaryReport
}

func (s *SlackReporter) SendSummaryReport(
	header string,
	numRepos int,
	report VulnerabilityReport,
	wg *sync.WaitGroup,
) error {
	defer wg.Done()
	summaryReport := s.buildSummaryReport(header, numRepos, report)
	wg.Add(1)
	go s.sendSlackMessage(s.config.Default_slack_channel, summaryReport, wg)
	return nil
}

func (s *SlackReporter) buildTeamReports(
	teamReports map[string]map[string]VulnerabilityReport,
	reportTime string,
) map[string]string {
	log := logger.Get()
	slackMessages := map[string]string{}

	severities := getSeverityReportOrder()
	for team, repos := range teamReports {
		teamReport := ""
		teamInfo, err := config.GetTeamConfigBySlug(team, s.config.Team)
		if err != nil {
			log.Warn().Str("team", team).Msg("Skipping report for unconfigured team.")
			continue
		}
		// Retrieve the list of repo names so that we can report alphabetically
		repoNames := maps.Keys(repos)
		sort.Strings(repoNames)
		for _, name := range repoNames {
			repo := repos[name]
			if name == SUMMARY_KEY {
				continue
			}
			repoReport := fmt.Sprintf("*%s* -- ", name)
			for _, severity := range severities {
				count := repo.VulnsBySeverity[severity]
				icon, err := config.GetIconForSeverity(severity, s.config.Severity)
				if err != nil {
					icon = DEFAULT_SLACK_ICON
				}
				repoReport += fmt.Sprintf("%s *%s*: %d ", icon, severity, count)
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
		teamReport = teamSummaryReport + teamReport
		if teamInfo.Slack_channel != "" {
			slackMessages[teamInfo.Slack_channel] = teamReport
		} else {
			log.Debug().Str("team", team).Str("teamReport", teamReport).Msg("Discarding team report because no Slack channel configured.")
		}
	}
	return slackMessages
}

func (s *SlackReporter) SendTeamReports(
	teamReports map[string]map[string]VulnerabilityReport,
	wg *sync.WaitGroup,
) error {
	defer wg.Done()

	reportTime := s.GetReportTime()
	slackMessages := s.buildTeamReports(teamReports, reportTime)
	for channel, message := range slackMessages {
		wg.Add(1)
		go s.sendSlackMessage(channel, message, wg)
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

func NewSlackReporter(config config.TomlConfig, slackToken string) (SlackReporter, error) {
	if slackToken == "" {
		return SlackReporter{}, fmt.Errorf("No Slack token was provided.")
	}
	client := slack.New(slackToken, slack.OptionDebug(true))
	return SlackReporter{config: config, client: client}, nil
}
