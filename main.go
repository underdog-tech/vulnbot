package main

import (
	"context"
	"dependabot-alert-bot/logger"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/shurcooL/githubv4"
	"github.com/slack-go/slack"
	"golang.org/x/oauth2"
)

// Used to represent repositories whose owner cannot be automatically detected
const NO_OWNER_KEY = "__none__"
const SUMMARY_KEY = "summary"

func tallyVulnsBySeverity(vulns []vulnerabilityAlert, vulnCounts map[string]int) {
	for _, vuln := range vulns {
		severity := strings.Title(strings.ToLower(vuln.SecurityVulnerability.Severity))
		vulnCounts[severity] += 1
	}
}

func tallyVulnsByEcosystem(vulns []vulnerabilityAlert, vulnCounts map[string]int) {
	for _, vuln := range vulns {
		ecosystem := strings.Title(strings.ToLower(vuln.SecurityVulnerability.Package.Ecosystem))
		_, exists := vulnCounts[ecosystem]
		if !exists {
			vulnCounts[ecosystem] = 0
		}
		vulnCounts[ecosystem] += 1
	}
}

func NewSeverityMap() map[string]int {
	return map[string]int{
		"Critical": 0,
		"High":     0,
		"Moderate": 0,
		"Low":      0,
	}
}

func getRepositoryOwners(repoName string, repositoryOwners map[string][]string) []string {
	log := logger.Get()
	owners, exists := repositoryOwners[repoName]
	if !exists {
		log.Warn().Str("repo", repoName).Msg("No owners found for repository.")
		return []string{}
	}
	return owners
}

type vulnerabilityReport struct {
	TotalCount       int
	AffectedRepos    int
	VulnsByEcosystem map[string]int
	VulnsBySeverity  map[string]int
}

func NewVulnerabilityReport() vulnerabilityReport {
	return vulnerabilityReport{
		AffectedRepos:    0,
		TotalCount:       0,
		VulnsBySeverity:  NewSeverityMap(),
		VulnsByEcosystem: map[string]int{},
	}
}

func collateSummaryReport(repos []vulnerabilityRepository) (report vulnerabilityReport) {
	log := logger.Get()
	report = NewVulnerabilityReport()
	for _, repo := range repos {
		repoVulns := repo.VulnerabilityAlerts.TotalCount
		report.TotalCount += repoVulns
		if repoVulns > 0 {
			report.AffectedRepos += 1
		}
		tallyVulnsBySeverity(repo.VulnerabilityAlerts.Nodes, report.VulnsBySeverity)
		tallyVulnsByEcosystem(repo.VulnerabilityAlerts.Nodes, report.VulnsByEcosystem)
	}
	log.Debug().Any("report", report).Msg("Collated summary report.")
	return report
}

func collateTeamReports(repos []vulnerabilityRepository, owners map[string][]string) (teamReports map[string]map[string]vulnerabilityReport) {
	log := logger.Get()

	vulnsByTeam := map[string][]vulnerabilityRepository{}
	// First, group up the repositories by owner
	for _, repo := range repos {
		owners := getRepositoryOwners(repo.Name, owners)
		if len(owners) == 0 {
			owners = []string{NO_OWNER_KEY}
		}
		for _, slug := range owners {
			_, exists := vulnsByTeam[slug]
			if !exists {
				vulnsByTeam[slug] = make([]vulnerabilityRepository, 0)
			}
			vulnsByTeam[slug] = append(vulnsByTeam[slug], repo)
		}
	}
	// Then create a report for each owner
	teamReports = map[string]map[string]vulnerabilityReport{}
	for team, repos := range vulnsByTeam {
		_, exists := teamReports[team]
		if !exists {
			teamReports[team] = map[string]vulnerabilityReport{}
		}
		teamReports[team][SUMMARY_KEY] = NewVulnerabilityReport()
		for _, repo := range repos {
			summaryReport, _ := teamReports[team][SUMMARY_KEY]
			summaryReport.AffectedRepos += 1
			repoReport := NewVulnerabilityReport()
			tallyVulnsByEcosystem(repo.VulnerabilityAlerts.Nodes, repoReport.VulnsByEcosystem)
			tallyVulnsByEcosystem(repo.VulnerabilityAlerts.Nodes, summaryReport.VulnsByEcosystem)
			tallyVulnsBySeverity(repo.VulnerabilityAlerts.Nodes, repoReport.VulnsBySeverity)
			for severity, count := range repoReport.VulnsBySeverity {
				summaryReport.VulnsBySeverity[severity] += count
				summaryReport.TotalCount += count
				repoReport.TotalCount += count
			}
			teamReports[team][SUMMARY_KEY] = summaryReport
			teamReports[team][repo.Name] = repoReport
		}
		log.Debug().Str("team", team).Any("teamReport", teamReports[team]).Msg("Completed team report.")
	}
	return teamReports
}

func main() {
	log := logger.Get()

	// Load the configuration file
	config := loadConfig()

	// Gather credentials from the environment
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal().Msg("Error loading .env file")
	}

	ghTokenSource := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)
	ghOrgLogin := os.Getenv("GITHUB_ORG")
	slackToken := os.Getenv("SLACK_AUTH_TOKEN")

	httpClient := oauth2.NewClient(context.Background(), ghTokenSource)
	ghClient := githubv4.NewClient(httpClient)

	ghOrgName, allRepos := queryGithubOrgVulnerabilities(ghOrgLogin, *ghClient)
	repositoryOwners := queryGithubOrgRepositoryOwners(ghOrgLogin, *ghClient)
	// Count our vulnerabilities
	log.Info().Msg("Collating results.")

	summaryReport := collateSummaryReport(allRepos)
	collateTeamReports(allRepos, repositoryOwners)

	vulnsBySeverity := NewSeverityMap()
	vulnsByEcosystem := map[string]int{}
	vulnsByTeam := map[string][]vulnerabilityRepository{}

	for _, repo := range allRepos {
		repoVulns := repo.VulnerabilityAlerts.TotalCount
		owners := getRepositoryOwners(repo.Name, repositoryOwners)
		if repoVulns > 0 && len(owners) > 0 {
			for _, slug := range owners {
				_, exists := vulnsByTeam[slug]
				if !exists {
					vulnsByTeam[slug] = make([]vulnerabilityRepository, 0)
				}
				vulnsByTeam[slug] = append(vulnsByTeam[slug], repo)
			}
		}
	}

	log.Debug().Any("vulnsByTeam", vulnsByTeam).Msgf("Identified %d distinct teams", len(vulnsByTeam))
	reportTime := time.Now().Format(time.RFC1123)
	summary := fmt.Sprintf("*%s Dependabot Report for %s*\nTotal repositories: %d\nTotal vulnerabilities: %d\nAffected repositories: %d\n", ghOrgName, reportTime, len(allRepos), summaryReport.TotalCount, summaryReport.AffectedRepos)

	severityReport := "*Breakdown by Severity*\n"
	for severity, vulnCount := range vulnsBySeverity {
		icon := getIconForSeverity(severity, config.Severity)
		severityReport = fmt.Sprintf("%s%s %s: %d\n", severityReport, icon, severity, vulnCount)
	}

	ecosystemReport := "*Breakdown by Ecosystem*\n"
	for ecosystem, vulnCount := range vulnsByEcosystem {
		icon := getIconForEcosystem(ecosystem, config.Ecosystem)
		ecosystemReport = fmt.Sprintf("%s%s %s: %d\n", ecosystemReport, icon, ecosystem, vulnCount)
	}

	fullReport := fmt.Sprintf("%s\n%s\n%s", summary, severityReport, ecosystemReport)

	slackMessages := map[string]string{
		config.Default_slack_channel: fullReport,
	}

	for team, repos := range vulnsByTeam {
		teamVulnsBySeverity := NewSeverityMap()
		teamVulnsByEcosystem := map[string]int{}
		totalVulns := 0
		teamReport := ""
		teamInfo := getTeamConfigBySlug(team, config.Team)
		for _, repo := range repos {
			repoVulnsBySeverity := NewSeverityMap()
			tallyVulnsBySeverity(repo.VulnerabilityAlerts.Nodes, repoVulnsBySeverity)
			repoReport := fmt.Sprintf("*%s* -- ", repo.Name)
			for severity, count := range repoVulnsBySeverity {
				teamVulnsBySeverity[severity] += count
				totalVulns += count
				repoReport += fmt.Sprintf("*%s %s*: %d ", getIconForSeverity(severity, config.Severity), severity, count)
			}
			repoReport += "\n"
			tallyVulnsByEcosystem(repo.VulnerabilityAlerts.Nodes, teamVulnsByEcosystem)
			teamReport += repoReport
		}
		if reflect.DeepEqual(teamInfo, teamConfig{}) {
			log.Warn().Str("team", team).Msg("Skipping report for unconfigured team.")
			continue
		}
		teamSummary := fmt.Sprintf("*%s Dependabot Report for %s*\nAffected repositories: %d\nTotal vulnerabilities: %d\n", teamInfo.Name, reportTime, len(repos), totalVulns)
		teamReport = teamSummary + teamReport + "\n"
		if teamInfo.Slack_channel != "" {
			slackMessages[teamInfo.Slack_channel] = teamReport
		} else {
			log.Debug().Str("team", team).Str("teamReport", teamReport).Msg("Discarding team report because no Slack channel configured.")
		}
	}

	log.Debug().Any("slackMessages", slackMessages).Msg("Messages generated for Slack.")
	if len(slackToken) > 0 {
		slackClient := slack.New(slackToken, slack.OptionDebug(true))
		for channel, message := range slackMessages {
			_, timestamp, err := slackClient.PostMessage(
				channel,
				slack.MsgOptionText(message, false),
				slack.MsgOptionAsUser(true),
			)

			if err != nil {
				panic(err)
			}
			log.Info().Str("channel", channel).Str("timestamp", timestamp).Msg("Message sent to Slack.")
		}
	} else {
		log.Warn().Msg("No Slack token found. Skipping communication.")
	}
	log.Info().Msg("Done!")
}
