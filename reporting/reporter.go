package reporting

import "sync"

type Reporter interface {
	SendSummaryReport(
		header string,
		numRepos int,
		report VulnerabilityReport,
		reportTime int64,
		wg *sync.WaitGroup,
	) error
	SendTeamReports(
		teamReports map[string]map[string]VulnerabilityReport,
		reportTime int64,
		wg *sync.WaitGroup,
	) error
}
