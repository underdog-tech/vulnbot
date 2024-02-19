package internal

import (
	"fmt"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"

	"github.com/underdog-tech/vulnbot/configs"
	"github.com/underdog-tech/vulnbot/logger"
	"github.com/underdog-tech/vulnbot/reporting"
)

func Scan(cmd *cobra.Command, args []string) {
	log := logger.Get()

	// Load the configuration from file, CLI, and env
	configPath := getString(cmd.Flags(), "config")
	cfg, err := configs.GetUserConfig(configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration.")
	}
	log.Trace().Msg("Loaded unified Viper config")

	// Load and query all configured data sources
	dataSources := GetDataSources(&cfg)

	projects := QueryAllDataSources(&dataSources)

	log.Trace().Any("projects", projects).Msg("Gathered project information.")

	summary, projectSummaries := reporting.SummarizeFindings(projects)
	teamSummaries := reporting.GroupTeamFindings(projects, projectSummaries)

	// Load and report out to all configured reporters
	reporters := []reporting.Reporter{}

	if slices.Contains(cfg.Reporters, "slack") {
		slackReporter, err := reporting.NewSlackReporter(&cfg)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create Slack reporter.")
		} else {
			reporters = append(reporters, &slackReporter)
		}
	}

	if slices.Contains(cfg.Reporters, "console") {
		reporters = append(reporters, &reporting.ConsoleReporter{Config: &cfg})
	}

	reportTime := time.Now().UTC()
	wg := new(sync.WaitGroup)

	for _, reporter := range reporters {
		wg.Add(2)
		go func(currentReporter reporting.Reporter) {
			summaryReportHeader := fmt.Sprintf("%s %s %s", ":robot_face:", "Vulnbot Summary Report", ":robot_face:")
			err := currentReporter.SendSummaryReport(
				summaryReportHeader,
				len(projects.Projects),
				summary,
				reportTime,
				teamSummaries,
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
