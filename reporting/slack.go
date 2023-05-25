package reporting

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/underdog-tech/vulnbot/config"
	"github.com/underdog-tech/vulnbot/logger"
	"golang.org/x/exp/maps"

	"github.com/slack-go/slack"
)

type SlackReporter struct {
	slackToken string
	Config     config.TomlConfig
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
	reportTime string,
) slack.Message {
	reportBlocks := []slack.Block{
		slack.NewHeaderBlock(
			slack.NewTextBlockObject(slack.PlainTextType, header, false, false),
		),
		slack.NewDividerBlock(),
		slack.NewContextBlock("", slack.NewTextBlockObject(
			slack.PlainTextType, reportTime, false, false,
		)),
		slack.NewSectionBlock(
			slack.NewTextBlockObject(
				slack.MarkdownType,
				fmt.Sprintf(
					"*Total repositories:* %d\n"+
						"*Total vulnerabilities:* %d\n"+
						"*Affected repositories:* %d\n",
					numRepos,
					report.TotalCount,
					report.AffectedRepos,
				),
				false, false,
			),
			nil, nil,
		),
		slack.NewHeaderBlock(
			slack.NewTextBlockObject(slack.PlainTextType, "Breakdown by Severity", false, false),
		),
	}

	severities := getSeverityReportOrder()
	for _, severity := range severities {
		vulnCount, _ := report.VulnsBySeverity[severity]
		icon, err := config.GetIconForSeverity(severity, s.Config.Severity)
		if err != nil {
			icon = DEFAULT_SLACK_ICON
		}
		reportBlocks = append(reportBlocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(
				slack.MarkdownType,
				fmt.Sprintf("%s *%s:* %d", icon, severity, vulnCount),
				false, false,
			),
			nil, nil,
		))
	}

	reportBlocks = append(reportBlocks, slack.NewHeaderBlock(
		slack.NewTextBlockObject(slack.PlainTextType, "Breakdown by Ecosystem", false, false),
	))
	ecosystems := maps.Keys(report.VulnsByEcosystem)
	sort.Strings(ecosystems)
	for _, ecosystem := range ecosystems {
		vulnCount, _ := report.VulnsByEcosystem[ecosystem]
		icon, err := config.GetIconForEcosystem(ecosystem, s.Config.Ecosystem)
		if err != nil {
			icon = DEFAULT_SLACK_ICON
		}
		reportBlocks = append(reportBlocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(
				slack.MarkdownType,
				fmt.Sprintf("%s *%s:* %d", icon, ecosystem, vulnCount),
				false, false,
			),
			nil, nil,
		))
	}
	return slack.NewBlockMessage(reportBlocks...)
}

func (s *SlackReporter) SendSummaryReport(
	header string,
	numRepos int,
	report VulnerabilityReport,
	reportTime string,
	wg *sync.WaitGroup,
) error {
	defer wg.Done()
	summaryReport := s.buildSummaryReport(header, numRepos, report, reportTime)
	wg.Add(1)
	go s.sendSlackMessage(s.Config.Default_slack_channel, slack.MsgOptionBlocks(summaryReport.Blocks.BlockSet...), wg)
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
			severityIcon, err = config.GetIconForSeverity(severity, s.Config.Severity)
			if err != nil {
				severityIcon = DEFAULT_SLACK_ICON
			}
		}
		vulnCounts = append(vulnCounts, fmt.Sprintf("%2d %s", repoReport.VulnsBySeverity[severity], severity))
	}
	if severityIcon == "" {
		severityIcon, err = config.GetIconForSeverity("None", s.Config.Severity)
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

func (s *SlackReporter) buildTeamReport(
	teamID string,
	repos map[string]VulnerabilityReport,
	reportTime string,
) *SlackReport {
	log := logger.Get()
	teamInfo, err := config.GetTeamConfigBySlug(teamID, s.Config.Team)
	if err != nil {
		log.Warn().Err(err).Str("team", teamID).Msg("Skipping report for unconfigured team.")
		return nil
	}
	if teamInfo.Slack_channel == "" {
		log.Debug().Str("team", teamID).Any("repos", repos).Msg("Skipping report since Slack channel is not configured.")
		return nil
	}
	reportBlocks := []slack.Block{
		slack.NewHeaderBlock(
			slack.NewTextBlockObject(slack.PlainTextType, fmt.Sprintf("%s Vulnbot Report", teamInfo.Name), false, false),
		),
		slack.NewDividerBlock(),
		slack.NewContextBlock("", slack.NewTextBlockObject(
			slack.PlainTextType, reportTime, false, false,
		)),
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
	message := slack.NewBlockMessage(reportBlocks...)
	return &SlackReport{ChannelID: teamInfo.Slack_channel, Message: &message}
}

func (s *SlackReporter) buildAllTeamReports(
	teamReports map[string]map[string]VulnerabilityReport,
	reportTime string,
) []*SlackReport {
	slackMessages := []*SlackReport{}

	for team, repos := range teamReports {
		report := s.buildTeamReport(team, repos, reportTime)
		if report != nil {
			slackMessages = append(slackMessages, report)
		}
	}
	return slackMessages
}

func (s *SlackReporter) SendTeamReports(
	teamReports map[string]map[string]VulnerabilityReport,
	reportTime string,
	wg *sync.WaitGroup,
) error {
	defer wg.Done()

	slackMessages := s.buildAllTeamReports(teamReports, reportTime)
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

func NewSlackReporter(config config.TomlConfig, slackToken string) (SlackReporter, error) {
	if slackToken == "" {
		return SlackReporter{}, fmt.Errorf("No Slack token was provided.")
	}
	client := slack.New(slackToken, slack.OptionDebug(true))
	return SlackReporter{Config: config, client: client}, nil
}
