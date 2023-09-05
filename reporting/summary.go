package reporting

import (
	"github.com/underdog-tech/vulnbot/config"
	"github.com/underdog-tech/vulnbot/querying"
)

var SeverityNames = map[config.FindingSeverityType]string{
	config.FindingSeverityCritical:  "Critical",
	config.FindingSeverityHigh:      "High",
	config.FindingSeverityModerate:  "Moderate",
	config.FindingSeverityLow:       "Low",
	config.FindingSeverityInfo:      "Info",
	config.FindingSeverityUndefined: "Undefined",
}

// NewSeverityMap returns a map of finding severities all associated with a
// value of 0, meant to be populated with a count of findings in the relevant
// scope. Notably, this map does not include either "Info" or "Undefined"
// severities, as these are only reported if present.
func NewSeverityMap() map[config.FindingSeverityType]int {
	return map[config.FindingSeverityType]int{
		config.FindingSeverityCritical: 0,
		config.FindingSeverityHigh:     0,
		config.FindingSeverityModerate: 0,
		config.FindingSeverityLow:      0,
	}
}

// GetSeverityReportOrder returns the order in which we want to report severities.
// This is necessary because we cannot declare a constant array in Go.
func GetSeverityReportOrder() []config.FindingSeverityType {
	return []config.FindingSeverityType{
		config.FindingSeverityCritical,
		config.FindingSeverityHigh,
		config.FindingSeverityModerate,
		config.FindingSeverityLow,
		config.FindingSeverityInfo,
		config.FindingSeverityUndefined,
	}
}

type FindingSummary struct {
	TotalCount       int
	AffectedRepos    int
	VulnsByEcosystem map[config.FindingEcosystemType]int
	VulnsBySeverity  map[config.FindingSeverityType]int
}

type ProjectFindingSummary struct {
	FindingSummary

	Name string
}

// GetHighestCriticality looks for the severity level of the most critical
// vulnerability in a project.
func (r FindingSummary) GetHighestCriticality() config.FindingSeverityType {
	severities := GetSeverityReportOrder()
	for _, sev := range severities {
		count, exists := r.VulnsBySeverity[sev]
		if exists && count > 0 {
			return sev
		}
	}
	return config.FindingSeverityUndefined
}

func NewFindingSummary() FindingSummary {
	return FindingSummary{
		AffectedRepos:    0,
		TotalCount:       0,
		VulnsByEcosystem: map[config.FindingEcosystemType]int{},
		VulnsBySeverity:  NewSeverityMap(),
	}
}

func NewProjectFindingSummary(name string) ProjectFindingSummary {
	summary := NewFindingSummary()
	return ProjectFindingSummary{Name: name, FindingSummary: summary}
}

func SummarizeFindings(projects *querying.ProjectCollection) (FindingSummary, []ProjectFindingSummary) {
	affectedRepos, vulnCount := 0, 0
	summary := NewFindingSummary()
	projectReportCollection := []ProjectFindingSummary{}

	for _, project := range projects.Projects {
		projectReport := NewProjectFindingSummary(project.Name)
		if numFindings := len(project.Findings); numFindings > 0 {
			affectedRepos += 1
			vulnCount += numFindings
			projectReport.AffectedRepos = 1
			projectReport.TotalCount = numFindings
			// For each finding, add its ecosystem and severity tally to both
			// the summary report and the project-specific report
			for _, finding := range project.Findings {
				summary.VulnsByEcosystem[finding.Ecosystem] += 1
				summary.VulnsBySeverity[finding.Severity] += 1

				projectReport.VulnsByEcosystem[finding.Ecosystem] += 1
				projectReport.VulnsBySeverity[finding.Severity] += 1
			}
		}
		projectReportCollection = append(projectReportCollection, projectReport)
	}
	summary.AffectedRepos = affectedRepos
	summary.TotalCount = vulnCount

	return summary, projectReportCollection
}

// TeamProjectCollection is a concrete type so that it can implement the sort
// interface, for custom sorting.
type TeamProjectCollection []*ProjectFindingSummary

func (r TeamProjectCollection) Len() int {
	return len(r)
}

func (r TeamProjectCollection) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

// Sort projects by criticality of findings, then by name
func (r TeamProjectCollection) Less(i, j int) bool {
	sevOne := r[i].GetHighestCriticality()
	sevTwo := r[j].GetHighestCriticality()
	if sevOne != sevTwo {
		return sevOne < sevTwo
	}
	return r[i].Name < r[j].Name
}

// GroupTeamFindings gathers a map of each team and the summaries of the projects
// that team "owns", and should receive reports for.
func GroupTeamFindings(projects *querying.ProjectCollection, summaries []ProjectFindingSummary) map[config.TeamConfig]TeamProjectCollection {
	teamProjects := map[config.TeamConfig]TeamProjectCollection{}

	for _, project := range projects.Projects {
		projectSummary := ProjectFindingSummary{}
		for _, sum := range summaries {
			if sum.Name == project.Name {
				projectSummary = sum
				break
			}
		}
		ownerIter := project.Owners.Iterator()
		for owner := range ownerIter.C {
			teamProjects[owner] = append(teamProjects[owner], &projectSummary)
		}
	}
	// We also need a summary report for each team
	for team, projects := range teamProjects {
		summaryReport := NewProjectFindingSummary(SUMMARY_KEY)
		for _, project := range projects {
			summaryReport.TotalCount += project.TotalCount
		}
		teamProjects[team] = append(teamProjects[team], &summaryReport)
	}
	return teamProjects
}
