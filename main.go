package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/shurcooL/githubv4"
	"github.com/slack-go/slack"
	"golang.org/x/oauth2"
)

var ecosystemIcons = map[string]string{
	"Go":       ":golang:",
	"Npm":      ":javascript:",
	"Pip":      ":python:",
	"Rubygems": ":ruby:",
}
var severityIcons = map[string]string{
	"Critical": ":severity_highest:",
	"High":     ":severity_high:",
	"Moderate": ":severity_medium:",
	"Low":      ":severity_low:",
}

func main() {
	// Gather configuration from the environment
	godotenv.Load(".env")

	ghTokenSource := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)
	ghOrgName := os.Getenv("GITHUB_ORG")
	slackToken := os.Getenv("SLACK_AUTH_TOKEN")
	channelID := os.Getenv("SLACK_CHANNEL_ID")

	httpClient := oauth2.NewClient(context.Background(), ghTokenSource)
	ghClient := githubv4.NewClient(httpClient)
	slackClient := slack.New(slackToken, slack.OptionDebug(true))

	// Construct the variables necessary for our GraphQL query
	queryVars := map[string]interface{}{
		"login":       githubv4.String(ghOrgName),
		"reposCursor": (*githubv4.String)(nil), // Null after argument to get first page
	}

	// Gather all repositories, handling pagination
	var allRepos []repository
	for {
		fmt.Println("Executing query against GitHub API.")
		err := ghClient.Query(context.Background(), &alertQuery, queryVars)
		if err != nil {
			panic(err)
		}
		allRepos = append(allRepos, alertQuery.Organization.Repositories.Nodes...)
		if !alertQuery.Organization.Repositories.PageInfo.HasNextPage {
			break
		}
		queryVars["reposCursor"] = githubv4.NewString(alertQuery.Organization.Repositories.PageInfo.EndCursor)
	}

	// Count our vulnerabilities
	fmt.Println("Collating results.")
	var totalVulns int
	var affectedRepos int
	// We want these in a specific order, and always report empty elements
	vulnsBySeverity := map[string]int{
		"Critical": 0,
		"High":     0,
		"Moderate": 0,
		"Low":      0,
	}
	vulnsByEcosystem := map[string]int{}

	for _, repo := range allRepos {
		repoVulns := repo.VulnerabilityAlerts.TotalCount
		totalVulns += repoVulns
		if repoVulns > 0 {
			affectedRepos += 1
		}
		for _, vuln := range repo.VulnerabilityAlerts.Nodes {
			// Tally by severity
			severity := strings.Title(strings.ToLower(vuln.SecurityVulnerability.Severity))
			vulnsBySeverity[severity] += 1

			// Tally by ecosystem
			ecosystem := strings.Title(strings.ToLower(vuln.SecurityVulnerability.Package.Ecosystem))
			_, exists := vulnsByEcosystem[ecosystem]
			if !exists {
				vulnsByEcosystem[ecosystem] = 0
			}
			vulnsByEcosystem[ecosystem] += 1
		}
	}

	reportTime := time.Now().Format(time.RFC1123)
	summary := fmt.Sprintf("*%s Dependabot Report for %s*\nTotal repositories: %d\nTotal vulnerabilities: %d\nAffected repositories: %d\n", alertQuery.Organization.Name, reportTime, alertQuery.Organization.Repositories.TotalCount, totalVulns, affectedRepos)
	fmt.Print(summary)

	severityReport := "*Breakdown by Severity*\n"
	for severity, vulnCount := range vulnsBySeverity {
		icon, exists := severityIcons[severity]
		if !exists {
			icon = ""
		}
		severityReport = fmt.Sprintf("%s%s %s: %d\n", severityReport, icon, severity, vulnCount)
	}
	fmt.Print(severityReport)

	ecosystemReport := "*Breakdown by Ecosystem*\n"
	for ecosystem, vulnCount := range vulnsByEcosystem {
		icon, exists := ecosystemIcons[ecosystem]
		if !exists {
			icon = ""
		}
		ecosystemReport = fmt.Sprintf("%s%s %s: %d\n", ecosystemReport, icon, ecosystem, vulnCount)
	}
	fmt.Print(ecosystemReport)

	fullReport := fmt.Sprintf("%s\n%s\n%s", summary, severityReport, ecosystemReport)
	_, timestamp, err := slackClient.PostMessage(
		channelID,
		slack.MsgOptionText(fullReport, false),
		slack.MsgOptionAsUser(true),
	)

	if err != nil {
		panic(err)
	}
	fmt.Printf("Message sent at %s", timestamp)
}
