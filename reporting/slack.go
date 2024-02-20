package reporting

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/slack-go/slack"
	"golang.org/x/exp/maps"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/underdog-tech/vulnbot/configs"
	"github.com/underdog-tech/vulnbot/logger"
)

type SlackReporter struct {
	Config *configs.Config
	Client SlackClientInterface
}

type SlackReport struct {
	ChannelID string
	Message   *slack.Message
}

type SlackClientInterface interface {
	PostMessage(channelID string, options ...slack.MsgOption) (string, string, error)
}

func (s *SlackReporter) BuildSummaryReport(
	header string,
	numRepos int,
	report FindingSummary,
	reportTime time.Time,
	teamSummaries TeamSummaries,
) slack.Message {
	reportBlocks := []slack.Block{
		slack.NewHeaderBlock(
			slack.NewTextBlockObject(slack.PlainTextType, header, false, false),
		),
		slack.NewContextBlock("", slack.NewTextBlockObject(
			slack.PlainTextType, reportTime.Format(DATE_LAYOUT), false, false,
		)),
		slack.NewSectionBlock(
			slack.NewTextBlockObject(
				slack.MarkdownType,
				fmt.Sprintf(
					"*Total Vulnerabilities:* %d\n"+
						"*Affected Repositories:* %d\n"+
						"*Total Repositories:* %d\n",
					report.TotalCount,
					report.AffectedRepos,
					numRepos,
				),
				false, false,
			),
			nil, nil,
		),
		slack.NewHeaderBlock(
			slack.NewTextBlockObject(slack.PlainTextType, "Team Breakdown", false, false),
		),
		slack.NewDividerBlock(),
	}

	// Generate Team Breakdown
	reportBlocks = s.generateTeamReport(reportBlocks, teamSummaries)

	// Generate Severity Breakdown
	reportBlocks = s.generateSeverityReport(reportBlocks, report)

	// Generate Ecosystem Breakdown
	reportBlocks = s.generateEcosystemReport(reportBlocks, report)

	return slack.NewBlockMessage(reportBlocks...)
}

func (s *SlackReporter) SendSummaryReport(
	header string,
	numRepos int,
	report FindingSummary,
	reportTime time.Time,
	teamSummaries TeamSummaries,
	wg *sync.WaitGroup,
) error {
	defer wg.Done()
	summaryReport := s.BuildSummaryReport(header, numRepos, report, reportTime, teamSummaries)
	wg.Add(1)
	go s.SendSlackMessage(s.Config.Default_slack_channel, slack.MsgOptionBlocks(summaryReport.Blocks.BlockSet...), wg)
	return nil
}

func (s *SlackReporter) BuildTeamRepositoryReport(
	repoReport *ProjectFindingSummary,
) *slack.SectionBlock {
	var severityIcon string
	severities := configs.GetSeverityReportOrder()
	vulnCounts := make([]string, 0)
	for _, severity := range severities {
		vulnCount, exists := repoReport.VulnsBySeverity[severity]
		if exists {
			if vulnCount > 0 && severityIcon == "" {
				severityIcon = configs.GetIconForSeverity(severity, s.Config.Severity)
			}
			vulnCounts = append(vulnCounts, fmt.Sprintf("%2d %s", vulnCount, configs.SeverityNames[severity]))
		}
	}
	if severityIcon == "" {
		severityIcon = configs.GetIconForSeverity(configs.FindingSeverityUndefined, s.Config.Severity)
	}
	projLinks := make([]string, 0)
	for title, link := range repoReport.Project.Links {
		projLinks = append(projLinks, fmt.Sprintf("[<%s|%s>]", link, title))
	}
	projName := fmt.Sprintf("%s *%s*", severityIcon, repoReport.Project.Name)
	if len(projLinks) > 0 {
		projName = fmt.Sprintf("%s · %s", projName, strings.Join(projLinks, " "))
	}
	fields := []*slack.TextBlockObject{
		slack.NewTextBlockObject(slack.MarkdownType, projName, false, false),
		slack.NewTextBlockObject(slack.MarkdownType, strings.Join(vulnCounts, " | "), false, false),
	}
	return slack.NewSectionBlock(nil, fields, nil)
}

func (s *SlackReporter) BuildTeamReport(
	teamInfo configs.TeamConfig,
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
		if repo.Project.Name == SUMMARY_KEY {
			summaryReport = repo
			continue
		}
		reportBlocks = append(reportBlocks, s.BuildTeamRepositoryReport(repo))
	}

	// Prepend the header & summary to the collected report blocks
	reportBlocks = append([]slack.Block{
		slack.NewHeaderBlock(
			slack.NewTextBlockObject(slack.PlainTextType, fmt.Sprintf("%s Vulnbot Report", teamInfo.Name), false, false),
		),
		slack.NewDividerBlock(),
		slack.NewContextBlock("", slack.NewTextBlockObject(
			slack.PlainTextType, reportTime.Format(DATE_LAYOUT), false, false,
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
	teamReports map[configs.TeamConfig]TeamProjectCollection,
	reportTime time.Time,
) []*SlackReport {
	slackMessages := []*SlackReport{}

	for team, repos := range teamReports {
		report := s.BuildTeamReport(team, repos, reportTime)
		if report != nil {
			slackMessages = append(slackMessages, report)
		}
	}
	return slackMessages
}

func (s *SlackReporter) SendTeamReports(
	teamReports map[configs.TeamConfig]TeamProjectCollection,
	reportTime time.Time,
	wg *sync.WaitGroup,
) error {
	defer wg.Done()

	slackMessages := s.buildAllTeamReports(teamReports, reportTime)
	for _, message := range slackMessages {
		wg.Add(1)
		go s.SendSlackMessage(message.ChannelID, slack.MsgOptionBlocks(message.Message.Blocks.BlockSet...), wg)
	}
	return nil
}

func (s *SlackReporter) SendSlackMessage(channel string, message slack.MsgOption, wg *sync.WaitGroup) {
	defer wg.Done()
	log := logger.Get()
	if s.Client != nil {
		_, timestamp, err := s.Client.PostMessage(channel, message, slack.MsgOptionAsUser(true))
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
func NewSlackReporter(cfg *configs.Config) (SlackReporter, error) {
	if cfg.Slack_auth_token == "" {
		return SlackReporter{}, errors.New("No Slack token was provided!")
	}
	client := slack.New(cfg.Slack_auth_token, slack.OptionDebug(true))
	return SlackReporter{Config: cfg, Client: client}, nil
}

func (s *SlackReporter) generateTeamReport(reportBlocks []slack.Block, teamSummaries TeamSummaries) []slack.Block {
	teamsBreakdown := calculateTeamBreakdown(teamSummaries)

	// Sort teams based on the number of vulnerabilities.
	sort.Slice(teamsBreakdown, func(i, j int) bool {
		return teamsBreakdown[i].TotalVulnerabilities < teamsBreakdown[j].TotalVulnerabilities
	})

	for i, team := range teamsBreakdown {
		icon := getIconForTeam(i)
		severityBlocks := s.generateSeverityBlocks(team.SeverityBreakdown)

		count := team.TotalVulnerabilities
		reportBlocks = append(reportBlocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(
				slack.MarkdownType,
				fmt.Sprintf("%s *%s:* %d %s", icon, team.Name, count, GetVulnerabilityWord(count)),
				false, false,
			),
			nil, slack.NewAccessory(slack.NewOverflowBlockElement("", severityBlocks...)),
		))
	}

	return reportBlocks
}

func calculateTeamBreakdown(teamSummaries TeamSummaries) []TeamBreakdown {
	var teamsBreakdown []TeamBreakdown //nolint:prealloc

	for team, summary := range teamSummaries {
		teamsBreakdown = append(teamsBreakdown, TeamBreakdown{
			Name:                 team.Name,
			TotalVulnerabilities: summary.GetTeamSummaryReport().TotalCount,
			SeverityBreakdown:    summary.GetTeamSeverityBreakdown(),
		})
	}

	return teamsBreakdown
}

func getIconForTeam(index int) string {
	icons := []string{":first_place_medal:", ":second_place_medal:", ":third_place_medal:"}
	if index < len(icons) {
		return icons[index]
	}
	return ":large_blue_diamond:"
}

func (s *SlackReporter) generateSeverityBlocks(severityBreakdown map[configs.FindingSeverityType]int) []*slack.OptionBlockObject {
	var severityBlocks []*slack.OptionBlockObject //nolint:prealloc

	severities := configs.GetSeverityReportOrder()
	for _, severityType := range severities {
		severityIcon := configs.GetIconForSeverity(severityType, s.Config.Severity)
		severityCount, exists := severityBreakdown[severityType]
		if !exists {
			continue
		}

		overflowOptionText := slack.NewTextBlockObject(slack.PlainTextType, fmt.Sprintf("%s %v %s",
			severityIcon,
			severityCount,
			configs.SeverityNames[severityType]), true, false)
		overflowOption := slack.NewOptionBlockObject("value", overflowOptionText, nil)
		severityBlocks = append(severityBlocks, overflowOption)
	}
	return severityBlocks
}

func (s *SlackReporter) generateSeverityReport(reportBlocks []slack.Block, report FindingSummary) []slack.Block {
	reportBlocks = append(reportBlocks, slack.NewHeaderBlock(
		slack.NewTextBlockObject(slack.PlainTextType, "Severity Breakdown", false, false),
	))
	reportBlocks = append(reportBlocks, slack.NewDividerBlock())

	severities := configs.GetSeverityReportOrder()
	for _, severity := range severities {
		vulnCount, exists := report.VulnsBySeverity[severity]
		if exists {
			icon := configs.GetIconForSeverity(severity, s.Config.Severity)
			reportBlocks = append(reportBlocks, slack.NewSectionBlock(
				slack.NewTextBlockObject(
					slack.MarkdownType,
					fmt.Sprintf("%s *%s:* %d", icon, configs.SeverityNames[severity], vulnCount),
					false, false,
				),
				nil, nil,
			))
		}
	}

	return reportBlocks
}

func (s *SlackReporter) generateEcosystemReport(reportBlocks []slack.Block, report FindingSummary) []slack.Block {
	reportBlocks = append(reportBlocks, slack.NewHeaderBlock(
		slack.NewTextBlockObject(slack.PlainTextType, "Ecosystem Breakdown", false, false),
	))
	reportBlocks = append(reportBlocks, slack.NewDividerBlock())

	ecosystems := maps.Keys(report.VulnsByEcosystem)
	caser := cases.Title(language.English)
	sort.Slice(ecosystems, func(i, j int) bool { return ecosystems[i] < ecosystems[j] })
	for _, ecosystem := range ecosystems {
		vulnCount := report.VulnsByEcosystem[ecosystem]
		icon := configs.GetIconForEcosystem(ecosystem, s.Config.Ecosystem)
		reportBlocks = append(reportBlocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(
				slack.MarkdownType,
				fmt.Sprintf("%s *%s:* %d", icon, caser.String(string(ecosystem)), vulnCount),
				false, false,
			),
			nil, nil,
		))
	}

	return reportBlocks
}

func GetVulnerabilityWord(count int) string {
	word := "vulnerabilities"
	if count == 0 || count == 1 {
		word = "vulnerability"
	}
	return word
}
