package internal

import (
	"fmt"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"

	"github.com/underdog-tech/vulnbot/configs"
	"github.com/underdog-tech/vulnbot/logger"
	"github.com/underdog-tech/vulnbot/querying"
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
	dataSources, githubDataSource := GetDataSources(&cfg)

	projects := QueryAllDataSources(&dataSources)

	log.Trace().Any("projects", projects).Msg("Gathered project information.")

	summary, projectSummaries := reporting.SummarizeFindings(projects)
	teamSummaries := reporting.GroupTeamFindings(projects, projectSummaries)

	// Load and report out to all configured reporters
	reporters := []reporting.Reporter{}

	// Tracked separately (not just via the reporters slice above) so its
	// repo-ownership sync - a Notion-specific capability outside the
	// standard Reporter interface - can be dispatched below. See
	// SendRepoOwnershipReport's own comment for why this isn't just
	// another SendSummaryReport/SendTeamReports call.
	var notionReporter *reporting.NotionReporter

	if slices.Contains(cfg.Reporters, "slack") {
		slackReporter, err := reporting.NewSlackReporter(&cfg)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create Slack reporter.")
		} else {
			reporters = append(reporters, &slackReporter)
		}
	}

	if slices.Contains(cfg.Reporters, "notion") {
		nr, err := reporting.NewNotionReporter(&cfg)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create Notion reporter.")
		} else {
			reporters = append(reporters, &nr)
			notionReporter = &nr
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

	// The repo ownership registry needs the full, unfiltered project list
	// (every non-archived repo, owned or not) - GroupTeamFindings only
	// ever hands teamSummaries the repos a team actually owns, so an
	// unowned repo would never reach this through the loop above. Runs
	// alongside the other reporters via the same WaitGroup rather than
	// sequentially after them.
	//
	// Forked repos are appended in separately from githubDataSource's
	// ForkProjects (nil if GitHub querying isn't configured at all):
	// they're deliberately excluded from projects.Projects itself (kept
	// out of vulnerability scanning entirely), but the person still wants
	// them visible in the ownership registry specifically. This is the
	// one place those two lists get combined - projects.Projects itself
	// is left untouched, so nothing else (SummarizeFindings,
	// GroupTeamFindings, and everything downstream of them) is affected.
	if notionReporter != nil {
		// A fresh copy, not append(projects.Projects, ...) directly: the
		// other reporters' goroutines above are still concurrently
		// reading projects.Projects at this point (e.g. via
		// len(projects.Projects) inside SendSummaryReport's call, which
		// only evaluates once its goroutine actually runs, not when it's
		// dispatched). Appending onto a slice built from
		// projects.Projects risks writing into its backing array's spare
		// capacity while another goroutine reads from that same array -
		// not obviously wrong, but not worth reasoning through under
		// concurrency when a plain copy sidesteps the question entirely.
		ownershipProjects := make([]*querying.Project, len(projects.Projects))
		copy(ownershipProjects, projects.Projects)
		if githubDataSource != nil {
			ownershipProjects = append(ownershipProjects, githubDataSource.ForkProjects.Projects...)
		}

		wg.Add(1)
		go func() {
			if err := notionReporter.SendRepoOwnershipReport(ownershipProjects, wg); err != nil {
				log.Error().Err(err).Msg("Error sending Notion repo ownership report.")
			}
		}()
	}

	wg.Wait()
	log.Info().Msg("Done!")
}