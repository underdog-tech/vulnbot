package internal

import (
	"sync"
	"time"

	"github.com/underdog-tech/vulnbot/config"
	"github.com/underdog-tech/vulnbot/logger"
	"github.com/underdog-tech/vulnbot/querying"
	"github.com/underdog-tech/vulnbot/reporting"

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

	// Load and query all configured data sources
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

	summary, projectSummaries := reporting.SummarizeFindings(projects)
	teamSummaries := reporting.GroupTeamFindings(projects, projectSummaries)

	// Load and report out to all configured reporters
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

	wg := new(sync.WaitGroup)
	for _, reporter := range reporters {
		wg.Add(2)
		go func(currentReporter reporting.Reporter) {
			err := currentReporter.SendSummaryReport(
				"Vulnbot Summary Report",
				len(projects.Projects),
				summary,
				reportTime,
				wg,
			)
			if err != nil {
				log.Error().Err(err).Type("currentReporter", currentReporter).Msg("Error sending summary report.")
			}
			err = currentReporter.SendTeamReports(teamSummaries, reportTime, wg)
			if err != nil {
				log.Error().Err(err).Type("currentReporters", currentReporter).Msg("Error sending team reports.")
			}
		}(reporter)
	}
	wg.Wait()
	log.Info().Msg("Done!")
}
