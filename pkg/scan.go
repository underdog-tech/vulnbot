package pkg

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"dependabot-alert-bot/api"
	"dependabot-alert-bot/configs"
	"dependabot-alert-bot/logger"

	"github.com/joho/godotenv"
	"github.com/shurcooL/githubv4"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

// Used to represent repositories whose owner cannot be automatically detected
const NO_OWNER_KEY = "__none__"
const SUMMARY_KEY = "summary"

func tallyVulnsBySeverity(vulns []api.VulnerabilityAlert, vulnCounts map[string]int) {
	for _, vuln := range vulns {
		severity := strings.Title(strings.ToLower(vuln.SecurityVulnerability.Severity))
		vulnCounts[severity] += 1
	}
}

func tallyVulnsByEcosystem(vulns []api.VulnerabilityAlert, vulnCounts map[string]int) {
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

func collateSummaryReport(repos []api.VulnerabilityRepository) (report vulnerabilityReport) {
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

func groupVulnsByOwner(repos []api.VulnerabilityRepository, owners map[string][]string) map[string][]api.VulnerabilityRepository {
	vulnsByTeam := map[string][]api.VulnerabilityRepository{}
	// First, group up the repositories by owner
	for _, repo := range repos {
		owners := getRepositoryOwners(repo.Name, owners)
		if len(owners) == 0 {
			owners = []string{NO_OWNER_KEY}
		}
		for _, slug := range owners {
			_, exists := vulnsByTeam[slug]
			if !exists {
				vulnsByTeam[slug] = make([]api.VulnerabilityRepository, 0)
			}
			vulnsByTeam[slug] = append(vulnsByTeam[slug], repo)
		}
	}
	return vulnsByTeam
}

func collateTeamReports(vulnsByTeam map[string][]api.VulnerabilityRepository) (teamReports map[string]map[string]vulnerabilityReport) {
	log := logger.Get()

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

func Scan(cmd *cobra.Command, args []string) {
	log := logger.Get()

	// Load the configuration file
	config := configs.LoadConfig()

	// Gather credentials from the environment
	err := godotenv.Load(".env")
	if err != nil {
		log.Info().Err(err).Msg(".env file not loaded.")
	}

	ghTokenSource := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)
	ghOrgLogin := os.Getenv("GITHUB_ORG")
	slackToken := os.Getenv("SLACK_AUTH_TOKEN")

	httpClient := oauth2.NewClient(context.Background(), ghTokenSource)
	ghClient := githubv4.NewClient(httpClient)

	ghOrgName, allRepos := api.QueryGithubOrgVulnerabilities(ghOrgLogin, *ghClient)
	repositoryOwners := api.QueryGithubOrgRepositoryOwners(ghOrgLogin, *ghClient)
	// Count our vulnerabilities
	log.Info().Msg("Collating results.")

	vulnSummary := collateSummaryReport(allRepos)
	vulnsByTeam := groupVulnsByOwner(allRepos, repositoryOwners)
	teamReports := collateTeamReports(vulnsByTeam)

	reportTime := time.Now().Format(time.RFC1123)
	summaryReport := fmt.Sprintf(
		"*%s Dependabot Report for %s*\n"+
			"Total repositories: %d\n"+
			"Total vulnerabilities: %d\n"+
			"Affected repositories: %d\n",
		ghOrgName,
		reportTime,
		len(allRepos),
		vulnSummary.TotalCount, vulnSummary.AffectedRepos,
	)

	severityReport := "*Breakdown by Severity*\n"
	for severity, vulnCount := range vulnSummary.VulnsBySeverity {
		icon := configs.GetIconForSeverity(severity, config.Severity)
		severityReport = fmt.Sprintf("%s%s %s: %d\n", severityReport, icon, severity, vulnCount)
	}

	ecosystemReport := "*Breakdown by Ecosystem*\n"
	for ecosystem, vulnCount := range vulnSummary.VulnsByEcosystem {
		icon := configs.GetIconForEcosystem(ecosystem, config.Ecosystem)
		ecosystemReport = fmt.Sprintf("%s%s %s: %d\n", ecosystemReport, icon, ecosystem, vulnCount)
	}

	summaryReport = fmt.Sprintf("%s\n%s\n%s", summaryReport, severityReport, ecosystemReport)

	slackMessages := map[string]string{
		config.Default_slack_channel: summaryReport,
	}

	for team, repos := range teamReports {
		teamReport := ""
		for name, repo := range repos {
			if name == SUMMARY_KEY {
				continue
			}
			repoReport := fmt.Sprintf("*%s* -- ", name)
			for severity, count := range repo.VulnsBySeverity {
				repoReport += fmt.Sprintf("*%s %s*: %d ", configs.GetIconForSeverity(severity, config.Severity), severity, count)
			}
			repoReport += "\n"
			teamReport += repoReport
		}
		teamInfo := configs.GetTeamConfigBySlug(team, config.Team)
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
		if reflect.DeepEqual(teamInfo, configs.TeamConfig{}) {
			log.Warn().Str("team", team).Msg("Skipping report for unconfigured team.")
			continue
		}
		if teamInfo.Slack_channel != "" {
			slackMessages[teamInfo.Slack_channel] = teamReport
		} else {
			log.Debug().Str("team", team).Str("teamReport", teamReport).Msg("Discarding team report because no Slack channel configured.")
		}
	}

	log.Debug().Any("slackMessages", slackMessages).Msg("Messages generated for Slack.")
	api.SendSlackMessages(slackToken, slackMessages)
	log.Info().Msg("Done!")
}
