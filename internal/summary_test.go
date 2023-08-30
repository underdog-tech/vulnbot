package internal_test

import (
	"sort"
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/stretchr/testify/assert"
	"github.com/underdog-tech/vulnbot/config"
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
					Ecosystem: config.FindingEcosystemGo,
					Severity:  config.FindingSeverityCritical,
					Identifiers: querying.FindingIdentifierMap{
						querying.FindingIdentifierCVE: "CVE-1",
					},
				},
				{
					Ecosystem: config.FindingEcosystemPython,
					Severity:  config.FindingSeverityHigh,
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
					Ecosystem: config.FindingEcosystemGo,
					Severity:  config.FindingSeverityInfo,
					Identifiers: querying.FindingIdentifierMap{
						querying.FindingIdentifierCVE: "CVE-3",
					},
				},
				{
					Ecosystem: config.FindingEcosystemJS,
					Severity:  config.FindingSeverityCritical,
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
	severities := config.NewSeverityMap()
	severities[config.FindingSeverityCritical] = 2
	severities[config.FindingSeverityHigh] = 1
	severities[config.FindingSeverityInfo] = 1
	expected := internal.FindingSummary{
		AffectedRepos: 2,
		TotalCount:    4,
		VulnsByEcosystem: map[config.FindingEcosystemType]int{
			config.FindingEcosystemGo:     2,
			config.FindingEcosystemJS:     1,
			config.FindingEcosystemPython: 1,
		},
		VulnsBySeverity: severities,
	}
	actual, _ := internal.SummarizeFindings(&testProjectFindings)
	assert.Equal(t, expected, actual)
}

func TestSummarizeGeneratesProjectReports(t *testing.T) {
	fooSeverities := config.NewSeverityMap()
	fooSeverities[config.FindingSeverityCritical] = 1
	fooSeverities[config.FindingSeverityHigh] = 1
	foo := internal.ProjectFindingSummary{
		Name: "foo",
		FindingSummary: internal.FindingSummary{
			AffectedRepos: 1,
			TotalCount:    2,
			VulnsByEcosystem: map[config.FindingEcosystemType]int{
				config.FindingEcosystemGo:     1,
				config.FindingEcosystemPython: 1,
			},
			VulnsBySeverity: fooSeverities,
		},
	}

	barSeverities := config.NewSeverityMap()
	barSeverities[config.FindingSeverityCritical] = 1
	barSeverities[config.FindingSeverityInfo] = 1
	bar := internal.ProjectFindingSummary{
		Name: "bar",
		FindingSummary: internal.FindingSummary{
			AffectedRepos: 1,
			TotalCount:    2,
			VulnsByEcosystem: map[config.FindingEcosystemType]int{
				config.FindingEcosystemGo: 1,
				config.FindingEcosystemJS: 1,
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

func TestGetHighestCriticality(t *testing.T) {
	severities := config.GetSeverityReportOrder()
	for _, severity := range severities {
		t.Run(string(severity), func(t *testing.T) {
			sevMap := config.NewSeverityMap()
			sevMap[severity] = 1
			summary := internal.ProjectFindingSummary{
				Name: "foo",
				FindingSummary: internal.FindingSummary{
					AffectedRepos:   1,
					TotalCount:      1,
					VulnsBySeverity: sevMap,
				},
			}
			assert.Equal(t, severity, summary.GetHighestCriticality())
		})
	}
}

func TestGetHighestCriticalityNoFindings(t *testing.T) {
	summary := internal.NewProjectFindingSummary("foo")
	assert.Equal(t, summary.GetHighestCriticality(), config.FindingSeverityUndefined)
}

func TestSortTeamProjectCollection(t *testing.T) {
	fooSeverities := config.NewSeverityMap()
	fooSeverities[config.FindingSeverityCritical] = 1
	fooSeverities[config.FindingSeverityHigh] = 1
	foo := internal.ProjectFindingSummary{
		Name: "foo",
		FindingSummary: internal.FindingSummary{
			AffectedRepos:   1,
			TotalCount:      2,
			VulnsBySeverity: fooSeverities,
		},
	}

	barSeverities := config.NewSeverityMap()
	barSeverities[config.FindingSeverityCritical] = 1
	barSeverities[config.FindingSeverityInfo] = 1
	bar := internal.ProjectFindingSummary{
		Name: "bar",
		FindingSummary: internal.FindingSummary{
			AffectedRepos:   1,
			TotalCount:      2,
			VulnsBySeverity: barSeverities,
		},
	}

	bazSeverities := config.NewSeverityMap()
	bazSeverities[config.FindingSeverityModerate] = 1
	baz := internal.ProjectFindingSummary{
		Name: "baz",
		FindingSummary: internal.FindingSummary{
			AffectedRepos:   1,
			TotalCount:      1,
			VulnsBySeverity: bazSeverities,
		},
	}

	// "bar" and "foo" both have critical, so should be first
	// baz only has moderate so should be second.
	expected := internal.TeamProjectCollection{&bar, &foo, &baz}
	actual := internal.TeamProjectCollection{&foo, &baz, &bar}

	sort.Sort(actual)
	assert.Equal(t, expected, actual)
}

func TestGroupTeamFindings(t *testing.T) {
	teamFoo := config.TeamConfig{
		Name:        "Team Foo",
		Github_slug: "foo",
	}
	teamBar := config.TeamConfig{
		Name:        "Team Bar",
		Github_slug: "bar",
	}
	teamBaz := config.TeamConfig{
		Name:        "The team known as Baz",
		Github_slug: "baz",
	}
	// Project "foo" will have 3 owners
	fooOwners := mapset.NewSet[config.TeamConfig]()
	fooOwners.Add(teamFoo)
	fooOwners.Add(teamBar)
	fooOwners.Add(teamBaz)
	testProjectFindings.Projects[0].Owners = fooOwners
	// Project "bar" will have 2 owners
	barOwners := mapset.NewSet[config.TeamConfig]()
	barOwners.Add(teamBar)
	barOwners.Add(teamBaz)
	testProjectFindings.Projects[1].Owners = barOwners
	// Project "baz" will have 1 owner
	bazOwners := mapset.NewSet[config.TeamConfig]()
	bazOwners.Add(teamBaz)
	testProjectFindings.Projects[2].Owners = bazOwners
	// Make sure to clear our ownership changes when the test is done
	defer func() {
		for _, proj := range testProjectFindings.Projects {
			proj.Owners = mapset.NewSet[config.TeamConfig]()
		}
	}()
	fooSummary := internal.NewProjectFindingSummary("foo")
	barSummary := internal.NewProjectFindingSummary("bar")
	bazSummary := internal.NewProjectFindingSummary("baz")
	summaries := []internal.ProjectFindingSummary{fooSummary, barSummary, bazSummary}

	expected := map[config.TeamConfig]internal.TeamProjectCollection{
		teamFoo: {&fooSummary},
		teamBar: {&fooSummary, &barSummary},
		teamBaz: {&fooSummary, &barSummary, &bazSummary},
	}

	actual := internal.GroupTeamFindings(&testProjectFindings, summaries)

	assert.Equal(t, expected, actual)
}
