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

func newSeverityMap() map[string]int {
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

func main() {
	log := logger.Get()

	// Load the configuration file
	config := loadConfig()

	// Gather credentials from the environment
	godotenv.Load(".env")

	log.Debug().Any("config", config).Msg("Loaded config.")

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
	var totalVulns int
	var affectedRepos int
	vulnsBySeverity := newSeverityMap()
	vulnsByEcosystem := map[string]int{}
	vulnsByTeam := map[string][]vulnerabilityRepository{}

	for _, repo := range allRepos {
		repoVulns := repo.VulnerabilityAlerts.TotalCount
		totalVulns += repoVulns
		if repoVulns > 0 {
			affectedRepos += 1
		}
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

		tallyVulnsBySeverity(repo.VulnerabilityAlerts.Nodes, vulnsBySeverity)
		tallyVulnsByEcosystem(repo.VulnerabilityAlerts.Nodes, vulnsByEcosystem)
	}

	log.Debug().Any("vulnsByTeam", vulnsByTeam).Msgf("Identified %d distinct teams", len(vulnsByTeam))
	reportTime := time.Now().Format(time.RFC1123)
	summary := fmt.Sprintf("*%s Dependabot Report for %s*\nTotal repositories: %d\nTotal vulnerabilities: %d\nAffected repositories: %d\n", ghOrgName, reportTime, len(allRepos), totalVulns, affectedRepos)

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
		teamVulnsBySeverity := newSeverityMap()
		teamVulnsByEcosystem := map[string]int{}
		totalVulns = 0
		teamReport := ""
		teamInfo := getTeamConfigBySlug(team, config.Team)
		for _, repo := range repos {
			repoVulnsBySeverity := newSeverityMap()
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
