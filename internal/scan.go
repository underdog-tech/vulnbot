package internal

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/shurcooL/githubv4"
	"github.com/underdog-tech/vulnbot/api"
	"github.com/underdog-tech/vulnbot/config"
	"github.com/underdog-tech/vulnbot/logger"
	"github.com/underdog-tech/vulnbot/reporting"
	"golang.org/x/oauth2"

	"github.com/spf13/cobra"
)

func Scan(cmd *cobra.Command, args []string) {
	log := logger.Get()

	// Load the configuration file
	configPath := getString(cmd.Flags(), "config")
	userConfig := config.Config{}
	err := config.LoadConfig(config.ViperParams{
		Output:     &userConfig,
		ConfigPath: &configPath,
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to load configuration.")
	}

	// Load ENV file
	env := config.Env{}
	envFileName := ".env"
	err = config.LoadEnv(config.ViperParams{
		Output:      &env,
		EnvFileName: &envFileName,
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to load ENV file.")
	}

	/****
	* NOTE: This is working code at the moment, but will remain commented out
	* until the collating and reporting has been updated to accept the new format.
	dataSources := []querying.DataSource{}

	if env.GithubToken != "" {
		ghds := querying.NewGithubDataSource(userConfig, env)
		dataSources = append(dataSources, &ghds)
	}

	dswg := new(sync.WaitGroup)
	projects := querying.NewProjectCollection()
	for _, ds := range dataSources {
		dswg.Add(1)
		go func(currentDS querying.DataSource) {
			err := currentDS.CollectFindings(projects, dswg)
			if err != nil {
				log.Error().Err(err).Type("datasource", currentDS).Msg("Failed to query datasource")
			}
		}(ds)
	}
	dswg.Wait()
	log.Trace().Any("projects", projects).Msg("Gathered project information.")
	*/

	slackToken := env.SlackAuthToken

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

	reportTime := time.Now().UTC()
	ghTokenSource := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: env.GithubToken},
	)
	httpClient := oauth2.NewClient(context.Background(), ghTokenSource)
	ghClient := githubv4.NewClient(httpClient)
	ghOrgLogin := env.GithubOrg
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
		go func(currentReporter reporting.Reporter) {
			err := currentReporter.SendSummaryReport(
				summaryHeader,
				len(allRepos),
				vulnSummary,
				reportTime,
				wg,
			)
			if err != nil {
				log.Error().Err(err).Type("currentReporter", currentReporter).Msg("Error sending summary report.")
			}
			err = currentReporter.SendTeamReports(teamReports, reportTime, wg)
			if err != nil {
				log.Error().Err(err).Type("currentReporters", currentReporter).Msg("Error sending team reports.")
			}
		}(reporter)
	}
	wg.Wait()
	log.Info().Msg("Done!")
}
