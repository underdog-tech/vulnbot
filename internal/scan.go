package internal

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/underdog-tech/vulnbot/api"
	"github.com/underdog-tech/vulnbot/config"
	"github.com/underdog-tech/vulnbot/logger"
	"github.com/underdog-tech/vulnbot/reporting"

	"github.com/joho/godotenv"
	"github.com/shurcooL/githubv4"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

func Scan(cmd *cobra.Command, args []string) {
	log := logger.Get(!logger.QuietLogger)

	// Load the configuration file
	configFilePath := getString(cmd.Flags(), "config")
	userConfig := config.LoadConfig(&configFilePath)

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

	reporters := []reporting.Reporter{}

	disableSlack := getBool(cmd.Flags(), "disable-slack")
	if !disableSlack {
		slackReporter, err := reporting.NewSlackReporter(userConfig, slackToken)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create Slack reporter.")
		} else {
			reporters = append(reporters, &slackReporter)
		}
	}
	reporters = append(reporters, &reporting.ConsoleReporter{Config: userConfig})

	reportTime := time.Now().Format(time.RFC1123)
	ghOrgName, allRepos := api.QueryGithubOrgVulnerabilities(ghOrgLogin, *ghClient)
	repositoryOwners := api.QueryGithubOrgRepositoryOwners(ghOrgLogin, *ghClient)
	// Count our vulnerabilities
	log.Info().Msg("Collating results.")

	vulnSummary := reporting.CollateSummaryReport(allRepos)
	vulnsByTeam := reporting.GroupVulnsByOwner(allRepos, repositoryOwners)
	teamReports := reporting.CollateTeamReports(vulnsByTeam)

	summaryHeader := fmt.Sprintf("%s Vulnbot Report", ghOrgName)

	wg := new(sync.WaitGroup)
	for _, reporter := range reporters {
		wg.Add(2)
		go reporter.SendSummaryReport(
			summaryHeader,
			len(allRepos),
			vulnSummary,
			reportTime,
			wg,
		)
		go reporter.SendTeamReports(teamReports, reportTime, wg)
	}
	wg.Wait()
	log.Info().Msg("Done!")
}
