package internal_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/underdog-tech/vulnbot/internal"
	"github.com/underdog-tech/vulnbot/querying"
)

// We want a fairly comprehensive collection, to generate a few different numbers
var testProjectFindings = querying.ProjectCollection{
	Projects: []*querying.Project{
		{
			Name: "foo",
			Findings: []*querying.Finding{
				{
					Ecosystem: querying.FindingEcosystemGo,
					Severity:  querying.FindingSeverityCritical,
					Identifiers: querying.FindingIdentifierMap{
						querying.FindingIdentifierCVE: "CVE-1",
					},
				},
				{
					Ecosystem: querying.FindingEcosystemPython,
					Severity:  querying.FindingSeverityHigh,
					Identifiers: querying.FindingIdentifierMap{
						querying.FindingIdentifierCVE: "CVE-2",
					},
				},
			},
		},
		{
			Name: "bar",
			Findings: []*querying.Finding{
				{
					Ecosystem: querying.FindingEcosystemGo,
					Severity:  querying.FindingSeverityInfo,
					Identifiers: querying.FindingIdentifierMap{
						querying.FindingIdentifierCVE: "CVE-3",
					},
				},
				{
					Ecosystem: querying.FindingEcosystemJS,
					Severity:  querying.FindingSeverityCritical,
					Identifiers: querying.FindingIdentifierMap{
						querying.FindingIdentifierCVE: "CVE-4",
					},
				},
			},
		},
		{
			Name:     "baz",
			Findings: []*querying.Finding{},
		},
	},
}

func TestSummarizeGeneratesOverallSummary(t *testing.T) {
	severities := internal.NewSeverityMap()
	severities[querying.FindingSeverityCritical] = 2
	severities[querying.FindingSeverityHigh] = 1
	severities[querying.FindingSeverityInfo] = 1
	expected := internal.FindingSummary{
		AffectedRepos: 2,
		TotalCount:    4,
		VulnsByEcosystem: map[querying.FindingEcosystemType]int{
			querying.FindingEcosystemGo:     2,
			querying.FindingEcosystemJS:     1,
			querying.FindingEcosystemPython: 1,
		},
		VulnsBySeverity: severities,
	}
	actual, _ := internal.SummarizeFindings(&testProjectFindings)
	assert.Equal(t, expected, actual)
}

func TestSummarizeGeneratesProjectReports(t *testing.T) {
	fooSeverities := internal.NewSeverityMap()
	fooSeverities[querying.FindingSeverityCritical] = 1
	fooSeverities[querying.FindingSeverityHigh] = 1
	foo := internal.ProjectFindingSummary{
		Name: "foo",
		FindingSummary: internal.FindingSummary{
			AffectedRepos: 1,
			TotalCount:    2,
			VulnsByEcosystem: map[querying.FindingEcosystemType]int{
				querying.FindingEcosystemGo:     1,
				querying.FindingEcosystemPython: 1,
			},
			VulnsBySeverity: fooSeverities,
		},
	}

	barSeverities := internal.NewSeverityMap()
	barSeverities[querying.FindingSeverityCritical] = 1
	barSeverities[querying.FindingSeverityInfo] = 1
	bar := internal.ProjectFindingSummary{
		Name: "bar",
		FindingSummary: internal.FindingSummary{
			AffectedRepos: 1,
			TotalCount:    2,
			VulnsByEcosystem: map[querying.FindingEcosystemType]int{
				querying.FindingEcosystemGo: 1,
				querying.FindingEcosystemJS: 1,
			},
			VulnsBySeverity: barSeverities,
		},
	}

	expected := []internal.ProjectFindingSummary{
		foo,
		bar,
		internal.NewProjectFindingSummary("baz"),
	}
	_, actual := internal.SummarizeFindings(&testProjectFindings)
	assert.Equal(t, expected, actual)
}
