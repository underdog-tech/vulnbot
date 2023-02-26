package main

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
	"github.com/shurcooL/githubv4"
	"github.com/slack-go/slack"
	"golang.org/x/oauth2"
)

type vulnerabilityAlert struct {
	Id                    string
	Number                int
	SecurityVulnerability struct {
		Severity string
		Package  struct {
			Ecosystem string
			Name      string
		}
	}
}

type repository struct {
	Name                string
	IsArchived          bool
	VulnerabilityAlerts struct {
		TotalCount int
		Nodes      []vulnerabilityAlert
	} `graphql:"vulnerabilityAlerts(first: 100, states: OPEN)"`
}

var alertQuery struct {
	Organization struct {
		Name         string
		Login        string
		Repositories struct {
			TotalCount int
			PageInfo   struct {
				EndCursor   githubv4.String
				HasNextPage bool
			}
			Nodes []repository
		} `graphql:"repositories(orderBy: {field: NAME, direction: ASC}, isFork: false, first: 100, after: $reposCursor)"`
	} `graphql:"organization(login: $login)"`
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
	var totalVulns int
	vulnCounts := map[string]int{
		"LOW":      0,
		"MODERATE": 0,
		"HIGH":     0,
		"CRITICAL": 0,
	}

	for _, repo := range allRepos {
		totalVulns += repo.VulnerabilityAlerts.TotalCount
		for _, vuln := range repo.VulnerabilityAlerts.Nodes {
			vulnCounts[vuln.SecurityVulnerability.Severity] += 1
		}
	}

	summaryAttachment := slack.Attachment{
		Text:  "Dependabot Vulnerability Report",
		Color: "569cd6",
		Fields: []slack.AttachmentField{
			{
				Title: "Org name",
				Value: alertQuery.Organization.Name,
			},
			{
				Title: "Total Repository Count",
				Value: strconv.Itoa(alertQuery.Organization.Repositories.TotalCount),
			},
			{
				Title: "Total Vulnerability Count",
				Value: strconv.Itoa(totalVulns),
			},
		},
	}
	criticalAttachment := slack.Attachment{
		Color: "f85149",
		Fields: []slack.AttachmentField{
			{
				Title: "Critical vulnerabilities",
				Value: strconv.Itoa(vulnCounts["CRITICAL"]),
			},
		},
	}
	highAttachment := slack.Attachment{
		Color: "db6d28",
		Fields: []slack.AttachmentField{
			{
				Title: "High vulnerabilities",
				Value: strconv.Itoa(vulnCounts["HIGH"]),
			},
		},
	}
	moderateAttachment := slack.Attachment{
		Color: "d29922",
		Fields: []slack.AttachmentField{
			{
				Title: "Moderate vulnerabilities",
				Value: strconv.Itoa(vulnCounts["MODERATE"]),
			},
		},
	}
	lowAttachment := slack.Attachment{
		Color: "c9d1d9",
		Fields: []slack.AttachmentField{
			{
				Title: "Low vulnerabilities",
				Value: strconv.Itoa(vulnCounts["LOW"]),
			},
		},
	}

	_, timestamp, err := slackClient.PostMessage(
		channelID,
		slack.MsgOptionAttachments(summaryAttachment, criticalAttachment, highAttachment, moderateAttachment, lowAttachment),
	)

	if err != nil {
		panic(err)
	}
	fmt.Printf("Message sent at %s", timestamp)
}
