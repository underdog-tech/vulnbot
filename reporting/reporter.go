package reporting

import "sync"

type Reporter interface {
	SendSummaryReport(
		header string,
		numRepos int,
		report VulnerabilityReport,
		reportTime string,
		wg *sync.WaitGroup,
	) error
	SendTeamReports(
		teamReports map[string]map[string]VulnerabilityReport,
		reportTime string,
		wg *sync.WaitGroup,
	) error
}
