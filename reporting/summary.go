package reporting

import (
	"github.com/underdog-tech/vulnbot/configs"
	"github.com/underdog-tech/vulnbot/querying"
)

var SeverityNames = map[configs.FindingSeverityType]string{
	configs.FindingSeverityCritical:  "Critical",
	configs.FindingSeverityHigh:      "High",
	configs.FindingSeverityModerate:  "Moderate",
	configs.FindingSeverityLow:       "Low",
	configs.FindingSeverityInfo:      "Info",
	configs.FindingSeverityUndefined: "Undefined",
}

// NewSeverityMap returns a map of finding severities all associated with a
// value of 0, meant to be populated with a count of findings in the relevant
// scope. Notably, this map does not include either "Info" or "Undefined"
// severities, as these are only reported if present.
func NewSeverityMap() map[configs.FindingSeverityType]int {
	return map[configs.FindingSeverityType]int{
		configs.FindingSeverityCritical: 0,
		configs.FindingSeverityHigh:     0,
		configs.FindingSeverityModerate: 0,
		configs.FindingSeverityLow:      0,
	}
}

// GetSeverityReportOrder returns the order in which we want to report severities.
// This is necessary because we cannot declare a constant array in Go.
func GetSeverityReportOrder() []configs.FindingSeverityType {
	return []configs.FindingSeverityType{
		configs.FindingSeverityCritical,
		configs.FindingSeverityHigh,
		configs.FindingSeverityModerate,
		configs.FindingSeverityLow,
		configs.FindingSeverityInfo,
		configs.FindingSeverityUndefined,
	}
}

type TeamSummaries map[configs.TeamConfig]TeamProjectCollection

type TeamBreakdown struct {
	Name                 string
	TotalVulnerabilities int
	SeverityBreakdown    map[configs.FindingSeverityType]int
}

type FindingSummary struct {
	TotalCount       int
	AffectedRepos    int
	VulnsByEcosystem map[configs.FindingEcosystemType]int
	VulnsBySeverity  map[configs.FindingSeverityType]int
}

type ProjectFindingSummary struct {
	FindingSummary

	Project *querying.Project
}

// GetHighestCriticality looks for the severity level of the most critical
// vulnerability in a project.
func (r FindingSummary) GetHighestCriticality() configs.FindingSeverityType {
	severities := GetSeverityReportOrder()
	for _, sev := range severities {
		count, exists := r.VulnsBySeverity[sev]
		if exists && count > 0 {
			return sev
		}
	}
	return configs.FindingSeverityUndefined
}

func NewFindingSummary() FindingSummary {
	return FindingSummary{
		AffectedRepos:    0,
		TotalCount:       0,
		VulnsByEcosystem: map[configs.FindingEcosystemType]int{},
		VulnsBySeverity:  NewSeverityMap(),
	}
}

func NewProjectFindingSummary(project *querying.Project) ProjectFindingSummary {
	summary := NewFindingSummary()
	return ProjectFindingSummary{Project: project, FindingSummary: summary}
}

func SummarizeFindings(projects *querying.ProjectCollection) (FindingSummary, []ProjectFindingSummary) {
	affectedRepos, vulnCount := 0, 0
	summary := NewFindingSummary()
	projectReportCollection := []ProjectFindingSummary{}

	for _, project := range projects.Projects {
		projectReport := NewProjectFindingSummary(project)
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

func (r TeamProjectCollection) GetTeamSummaryReport() *ProjectFindingSummary {
	var summaryReport *ProjectFindingSummary

	for _, repo := range r {
		if repo.Project.Name == SUMMARY_KEY {
			summaryReport = repo
			break
		}
	}
	return summaryReport
}

func (r TeamProjectCollection) GetTeamSeverityBreakdown() map[configs.FindingSeverityType]int {
	vulnCountsBySeverity := make(map[configs.FindingSeverityType]int)
	severities := configs.GetSeverityReportOrder()

	for _, repo := range r {
		if repo.Project.Name == SUMMARY_KEY {
			continue
		}

		for severity, count := range repo.VulnsBySeverity {
			severityType := severities[severity]
			vulnCountsBySeverity[severityType] += count
		}
	}

	return vulnCountsBySeverity
}

// Sort projects by criticality of findings, then by name
func (r TeamProjectCollection) Less(i, j int) bool {
	sevOne := r[i].GetHighestCriticality()
	sevTwo := r[j].GetHighestCriticality()
	if sevOne != sevTwo {
		return sevOne < sevTwo
	}
	return r[i].Project.Name < r[j].Project.Name
}

// GroupTeamFindings gathers a map of each team and the summaries of the projects
// that team "owns", and should receive reports for.
func GroupTeamFindings(projects *querying.ProjectCollection, summaries []ProjectFindingSummary) map[configs.TeamConfig]TeamProjectCollection {
	teamProjects := map[configs.TeamConfig]TeamProjectCollection{}

	for _, project := range projects.Projects {
		projectSummary := ProjectFindingSummary{}
		for _, sum := range summaries {
			if sum.Project == project {
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
		summaryReport := NewProjectFindingSummary(querying.NewProject(SUMMARY_KEY))
		for _, project := range projects {
			summaryReport.TotalCount += project.TotalCount
		}
		teamProjects[team] = append(teamProjects[team], &summaryReport)
	}
	return teamProjects
}
