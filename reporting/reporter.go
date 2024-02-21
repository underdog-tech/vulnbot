package reporting

import (
	"sync"
	"time"

	"github.com/underdog-tech/vulnbot/configs"
)

type Reporter interface {
	SendSummaryReport(
		header string,
		numRepos int,
		report FindingSummary,
		reportTime time.Time,
		teamSummaries TeamSummaries,
		wg *sync.WaitGroup,
	) error
	SendTeamReports(
		teamReports map[configs.TeamConfig]TeamProjectCollection,
		reportTime time.Time,
		wg *sync.WaitGroup,
	) error
}
