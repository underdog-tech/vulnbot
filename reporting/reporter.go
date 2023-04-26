package reporting

import "sync"

func NewSeverityMap() map[string]int {
	return map[string]int{
		"Critical": 0,
		"High":     0,
		"Moderate": 0,
		"Low":      0,
	}
}

type VulnerabilityReport struct {
	TotalCount       int
	AffectedRepos    int
	VulnsByEcosystem map[string]int
	VulnsBySeverity  map[string]int
}

func NewVulnerabilityReport() VulnerabilityReport {
	return VulnerabilityReport{
		AffectedRepos:    0,
		TotalCount:       0,
		VulnsBySeverity:  NewSeverityMap(),
		VulnsByEcosystem: map[string]int{},
	}
}

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
