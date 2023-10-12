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
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/slack-go/slack"
)

type SlackReporter struct {
	Config *config.Config
	client SlackClientInterface
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
	report FindingSummary,
	reportTime time.Time,
) slack.Message {
	reportBlocks := []slack.Block{
		slack.NewHeaderBlock(
			slack.NewTextBlockObject(slack.PlainTextType, header, false, false),
		),
		slack.NewDividerBlock(),
		slack.NewContextBlock("", slack.NewTextBlockObject(
			slack.PlainTextType, reportTime.Format(time.RFC1123), false, false,
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

	severities := config.GetSeverityReportOrder()
	for _, severity := range severities {
		vulnCount, exists := report.VulnsBySeverity[severity]
		if exists {
			icon, err := config.GetIconForSeverity(severity, s.Config.Severity)
			if err != nil {
				icon = DEFAULT_SLACK_ICON
			}
			reportBlocks = append(reportBlocks, slack.NewSectionBlock(
				slack.NewTextBlockObject(
					slack.MarkdownType,
					fmt.Sprintf("%s *%s:* %d", icon, config.SeverityNames[severity], vulnCount),
					false, false,
				),
				nil, nil,
			))
		}
	}

	reportBlocks = append(reportBlocks, slack.NewHeaderBlock(
		slack.NewTextBlockObject(slack.PlainTextType, "Breakdown by Ecosystem", false, false),
	))

	ecosystems := maps.Keys(report.VulnsByEcosystem)
	caser := cases.Title(language.English)
	sort.Slice(ecosystems, func(i, j int) bool { return ecosystems[i] < ecosystems[j] })

	for _, ecosystem := range ecosystems {
		vulnCount := report.VulnsByEcosystem[ecosystem]
		icon, err := config.GetIconForEcosystem(ecosystem, s.Config.Ecosystem)
		if err != nil {
			icon = DEFAULT_SLACK_ICON
		}
		reportBlocks = append(reportBlocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(
				slack.MarkdownType,
				fmt.Sprintf("%s *%s:* %d", icon, caser.String(string(ecosystem)), vulnCount),
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
	report FindingSummary,
	reportTime time.Time,
	wg *sync.WaitGroup,
) error {
	defer wg.Done()
	summaryReport := s.buildSummaryReport(header, numRepos, report, reportTime)
	wg.Add(1)
	go s.sendSlackMessage(s.Config.Default_slack_channel, slack.MsgOptionBlocks(summaryReport.Blocks.BlockSet...), wg)
	return nil
}

func (s *SlackReporter) buildTeamRepositoryReport(
	repoReport *ProjectFindingSummary,
) *slack.SectionBlock {
	var err error
	var severityIcon string
	severities := config.GetSeverityReportOrder()
	vulnCounts := make([]string, 0)
	for _, severity := range severities {
		vulnCount, exists := repoReport.VulnsBySeverity[severity]
		if exists {
			if vulnCount > 0 && severityIcon == "" {
				severityIcon, err = config.GetIconForSeverity(severity, s.Config.Severity)
				if err != nil {
					severityIcon = DEFAULT_SLACK_ICON
				}
			}
			vulnCounts = append(vulnCounts, fmt.Sprintf("%2d %s", vulnCount, config.SeverityNames[severity]))
		}
	}
	if severityIcon == "" {
		severityIcon, err = config.GetIconForSeverity(config.FindingSeverityUndefined, s.Config.Severity)
		if err != nil {
			severityIcon = DEFAULT_SLACK_ICON
		}
	}
	fields := []*slack.TextBlockObject{
		slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("%s *%s*", severityIcon, repoReport.Name), false, false),
		slack.NewTextBlockObject(slack.MarkdownType, strings.Join(vulnCounts, " | "), false, false),
	}
	return slack.NewSectionBlock(nil, fields, nil)
}

func (s *SlackReporter) buildTeamReport(
	teamInfo config.TeamConfig,
	repos TeamProjectCollection,
	reportTime time.Time,
) *SlackReport {
	log := logger.Get()
	if teamInfo.Slack_channel == "" {
		log.Debug().Str("team", teamInfo.Name).Any("repos", repos).Msg("Skipping report since Slack channel is not configured.")
		return nil
	}

	// Create Slack blocks for each individual repository
	reportBlocks := []slack.Block{}

	sort.Sort(repos)
	var summaryReport *ProjectFindingSummary
	for _, repo := range repos {
		if repo.Name == SUMMARY_KEY {
			summaryReport = repo
			continue
		}
		reportBlocks = append(reportBlocks, s.buildTeamRepositoryReport(repo))
	}

	// Prepend the header & summary to the collected report blocks
	reportBlocks = append([]slack.Block{
		slack.NewHeaderBlock(
			slack.NewTextBlockObject(slack.PlainTextType, fmt.Sprintf("%s Vulnbot Report", teamInfo.Name), false, false),
		),
		slack.NewDividerBlock(),
		slack.NewContextBlock("", slack.NewTextBlockObject(
			slack.PlainTextType, reportTime.Format(time.RFC1123), false, false,
		)),
		slack.NewSectionBlock(
			nil,
			[]*slack.TextBlockObject{
				slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("*%4d Total Vulnerabilities*", summaryReport.TotalCount), false, false),
				// TODO: Add a block with the breakdown by severity
			},
			nil,
		),
		slack.NewDividerBlock(),
	}, reportBlocks...)
	message := slack.NewBlockMessage(reportBlocks...)
	return &SlackReport{ChannelID: teamInfo.Slack_channel, Message: &message}
}

func (s *SlackReporter) buildAllTeamReports(
	teamReports map[config.TeamConfig]TeamProjectCollection,
	reportTime time.Time,
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
	teamReports map[config.TeamConfig]TeamProjectCollection,
	reportTime time.Time,
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

// NewSlackReporter returns a new SlackReporter instance for reporting out findings to a Slack server
func NewSlackReporter(cfg *config.Config) (SlackReporter, error) {
	if cfg.Slack_auth_token == "" {
		return SlackReporter{}, fmt.Errorf("No Slack token was provided.")
	}
	client := slack.New(cfg.Slack_auth_token, slack.OptionDebug(true))
	return SlackReporter{Config: cfg, client: client}, nil
}
