package reporting

import (
	"fmt"
	"sort"
	"strings"
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

type SlackReport struct {
	ChannelID string
	Message   *slack.Message
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
	ecosystems := maps.Keys(report.VulnsByEcosystem)
	sort.Strings(ecosystems)
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
	//summaryReport := s.buildSummaryReport(header, numRepos, report)
	// wg.Add(1)
	//go s.sendSlackMessage(s.config.Default_slack_channel, summaryReport, wg)
	return nil
}

func (s *SlackReporter) buildTeamRepositoryReport(
	repoName string,
	repoReport VulnerabilityReport,
) *slack.SectionBlock {
	var err error
	var severityIcon string
	severities := getSeverityReportOrder()
	vulnCounts := make([]string, 0)
	for _, severity := range severities {
		if severityIcon == "" && repoReport.VulnsBySeverity[severity] > 0 {
			severityIcon, err = config.GetIconForSeverity(severity, s.config.Severity)
			if err != nil {
				severityIcon = DEFAULT_SLACK_ICON
			}
		}
		vulnCounts = append(vulnCounts, fmt.Sprintf("%2d %s", repoReport.VulnsBySeverity[severity], severity))
	}
	if severityIcon == "" {
		severityIcon, err = config.GetIconForSeverity("None", s.config.Severity)
		if err != nil {
			severityIcon = DEFAULT_SLACK_ICON
		}
	}
	fields := []*slack.TextBlockObject{
		slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("%s *%s*", severityIcon, repoName), false, false),
		slack.NewTextBlockObject(slack.MarkdownType, strings.Join(vulnCounts, " | "), false, false),
	}
	return slack.NewSectionBlock(nil, fields, nil)
}

func (s *SlackReporter) buildTeamReports(
	teamReports map[string]map[string]VulnerabilityReport,
	reportTime string,
) []SlackReport {
	log := logger.Get()
	slackMessages := []SlackReport{}

	for team, repos := range teamReports {
		teamReport := ""
		teamInfo, err := config.GetTeamConfigBySlug(team, s.config.Team)
		if err != nil {
			log.Warn().Str("team", team).Msg("Skipping report for unconfigured team.")
			continue
		}
		reportBlocks := []slack.Block{
			slack.NewHeaderBlock(
				slack.NewTextBlockObject(slack.PlainTextType, fmt.Sprintf("%s Dependabot Report for %s", teamInfo.Name, reportTime), true, false),
			),
			slack.NewDividerBlock(),
			slack.NewSectionBlock(
				nil,
				[]*slack.TextBlockObject{
					slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("*%4d Total Vulnerabilities*", repos[SUMMARY_KEY].TotalCount), false, false),
					// TODO: Add a block with the breakdown by severity
				},
				nil,
			),
			slack.NewDividerBlock(),
		}
		// Retrieve the list of repo names so that we can report alphabetically
		repoNames := maps.Keys(repos)
		sort.Strings(repoNames)
		for _, name := range repoNames {
			repo := repos[name]
			if name == SUMMARY_KEY {
				continue
			}
			reportBlocks = append(reportBlocks, s.buildTeamRepositoryReport(name, repo))
		}
		if teamInfo.Slack_channel != "" {
			message := slack.NewBlockMessage(reportBlocks...)
			slackMessages = append(slackMessages, SlackReport{ChannelID: teamInfo.Slack_channel, Message: &message})
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
	for _, message := range slackMessages {
		wg.Add(1)
		go s.sendSlackMessage(message.ChannelID, slack.MsgOptionBlocks(message.Message.Blocks.BlockSet...), wg)
	}
	return nil
}

func (s *SlackReporter) sendSlackMessage(channel string, message slack.MsgOption, wg *sync.WaitGroup) {
	defer wg.Done()
	log := logger.Get()
	if s.client != nil {
		_, timestamp, err := s.client.PostMessage(channel, message, slack.MsgOptionAsUser(true))
		if err != nil {
			log.Error().Err(err).Msg("Failed to send Slack message.")
		} else {
			log.Info().Str("channel", channel).Str("timestamp", timestamp).Msg("Message sent to Slack.")
		}
	} else {
		log.Warn().Any("message", message).Str("channel", channel).Msg("No Slack client available. Message not sent.")
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
