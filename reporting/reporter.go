package reporting

import (
	"sync"
	"time"

	"github.com/underdog-tech/vulnbot/config"
)

type Reporter interface {
	SendSummaryReport(
		header string,
		numRepos int,
		report FindingSummary,
		reportTime time.Time,
		wg *sync.WaitGroup,
	) error
	SendTeamReports(
		teamReports map[config.TeamConfig]TeamProjectCollection,
		reportTime time.Time,
		wg *sync.WaitGroup,
	) error
}
