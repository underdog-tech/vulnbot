package reporting

import "sync"

type Reporter interface {
	SendSummaryReport(
		header string,
		numRepos int,
		report VulnerabilityReport,
		wg *sync.WaitGroup,
	) error
	SendTeamReports(
		teamReports map[string]map[string]VulnerabilityReport,
		wg *sync.WaitGroup,
	) error
}
