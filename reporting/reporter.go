package reporting

import (
	"sync"
	"time"
)

type Reporter interface {
	SendSummaryReport(
		header string,
		numRepos int,
		report VulnerabilityReport,
		reportTime time.Time,
		wg *sync.WaitGroup,
	) error
	SendTeamReports(
		teamReports map[string]map[string]VulnerabilityReport,
		reportTime time.Time,
		wg *sync.WaitGroup,
	) error
}
