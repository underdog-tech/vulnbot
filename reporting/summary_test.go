package reporting_test

import (
	"sort"
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/stretchr/testify/assert"

	"github.com/underdog-tech/vulnbot/configs"
	"github.com/underdog-tech/vulnbot/querying"
	"github.com/underdog-tech/vulnbot/reporting"
)

// We want a fairly comprehensive collection, to generate a few different numbers
var projFoo = querying.Project{
	Name: "foo",
	Findings: []*querying.Finding{
		{
			Ecosystem: configs.FindingEcosystemGo,
			Severity:  configs.FindingSeverityCritical,
			Identifiers: querying.FindingIdentifierMap{
				querying.FindingIdentifierCVE: "CVE-1",
			},
		},
		{
			Ecosystem: configs.FindingEcosystemPython,
			Severity:  configs.FindingSeverityHigh,
			Identifiers: querying.FindingIdentifierMap{
				querying.FindingIdentifierCVE: "CVE-2",
			},
		},
	},
}
var projBar = querying.Project{
	Name: "bar",
	Findings: []*querying.Finding{
		{
			Ecosystem: configs.FindingEcosystemGo,
			Severity:  configs.FindingSeverityInfo,
			Identifiers: querying.FindingIdentifierMap{
				querying.FindingIdentifierCVE: "CVE-3",
			},
		},
		{
			Ecosystem: configs.FindingEcosystemJS,
			Severity:  configs.FindingSeverityCritical,
			Identifiers: querying.FindingIdentifierMap{
				querying.FindingIdentifierCVE: "CVE-4",
			},
		},
	},
}
var projBaz = querying.Project{
	Name:     "baz",
	Findings: []*querying.Finding{},
}
var testProjectFindings = querying.ProjectCollection{
	Projects: []*querying.Project{
		&projFoo,
		&projBar,
		&projBaz,
	},
}

func TestSummarizeGeneratesOverallSummary(t *testing.T) {
	severities := reporting.NewSeverityMap()
	severities[configs.FindingSeverityCritical] = 2
	severities[configs.FindingSeverityHigh] = 1
	severities[configs.FindingSeverityInfo] = 1
	expected := reporting.FindingSummary{
		AffectedRepos: 2,
		TotalCount:    4,
		VulnsByEcosystem: map[configs.FindingEcosystemType]int{
			configs.FindingEcosystemGo:     2,
			configs.FindingEcosystemJS:     1,
			configs.FindingEcosystemPython: 1,
		},
		VulnsBySeverity: severities,
	}
	actual, _ := reporting.SummarizeFindings(&testProjectFindings)
	assert.Equal(t, expected, actual)
}

func TestSummarizeGeneratesProjectReports(t *testing.T) {
	fooSeverities := reporting.NewSeverityMap()
	fooSeverities[configs.FindingSeverityCritical] = 1
	fooSeverities[configs.FindingSeverityHigh] = 1
	foo := reporting.ProjectFindingSummary{
		Project: &projFoo,
		FindingSummary: reporting.FindingSummary{
			AffectedRepos: 1,
			TotalCount:    2,
			VulnsByEcosystem: map[configs.FindingEcosystemType]int{
				configs.FindingEcosystemGo:     1,
				configs.FindingEcosystemPython: 1,
			},
			VulnsBySeverity: fooSeverities,
		},
	}

	barSeverities := reporting.NewSeverityMap()
	barSeverities[configs.FindingSeverityCritical] = 1
	barSeverities[configs.FindingSeverityInfo] = 1
	bar := reporting.ProjectFindingSummary{
		Project: &projBar,
		FindingSummary: reporting.FindingSummary{
			AffectedRepos: 1,
			TotalCount:    2,
			VulnsByEcosystem: map[configs.FindingEcosystemType]int{
				configs.FindingEcosystemGo: 1,
				configs.FindingEcosystemJS: 1,
			},
			VulnsBySeverity: barSeverities,
		},
	}

	expected := []reporting.ProjectFindingSummary{
		foo,
		bar,
		reporting.NewProjectFindingSummary(&projBaz),
	}
	_, actual := reporting.SummarizeFindings(&testProjectFindings)
	assert.Equal(t, expected, actual)
}

func TestGetHighestCriticality(t *testing.T) {
	severities := reporting.GetSeverityReportOrder()
	for _, severity := range severities {
		t.Run(string(severity), func(t *testing.T) {
			sevMap := reporting.NewSeverityMap()
			sevMap[severity] = 1
			summary := reporting.ProjectFindingSummary{
				Project: &projFoo,
				FindingSummary: reporting.FindingSummary{
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
	summary := reporting.NewProjectFindingSummary(&projFoo)
	assert.Equal(t, summary.GetHighestCriticality(), configs.FindingSeverityUndefined)
}

func TestSortTeamProjectCollection(t *testing.T) {
	fooSeverities := reporting.NewSeverityMap()
	fooSeverities[configs.FindingSeverityCritical] = 1
	fooSeverities[configs.FindingSeverityHigh] = 1
	foo := reporting.ProjectFindingSummary{
		Project: &projFoo,
		FindingSummary: reporting.FindingSummary{
			AffectedRepos:   1,
			TotalCount:      2,
			VulnsBySeverity: fooSeverities,
		},
	}

	barSeverities := reporting.NewSeverityMap()
	barSeverities[configs.FindingSeverityCritical] = 1
	barSeverities[configs.FindingSeverityInfo] = 1
	bar := reporting.ProjectFindingSummary{
		Project: &projBar,
		FindingSummary: reporting.FindingSummary{
			AffectedRepos:   1,
			TotalCount:      2,
			VulnsBySeverity: barSeverities,
		},
	}

	bazSeverities := reporting.NewSeverityMap()
	bazSeverities[configs.FindingSeverityModerate] = 1
	baz := reporting.ProjectFindingSummary{
		Project: &projBaz,
		FindingSummary: reporting.FindingSummary{
			AffectedRepos:   1,
			TotalCount:      1,
			VulnsBySeverity: bazSeverities,
		},
	}

	// "bar" and "foo" both have critical, so should be first
	// baz only has moderate so should be second.
	expected := reporting.TeamProjectCollection{&bar, &foo, &baz}
	actual := reporting.TeamProjectCollection{&foo, &baz, &bar}

	sort.Sort(actual)
	assert.Equal(t, expected, actual)
}

func TestGroupTeamFindings(t *testing.T) {
	teamFoo := configs.TeamConfig{
		Name:        "Team Foo",
		Github_slug: "foo",
	}
	teamBar := configs.TeamConfig{
		Name:        "Team Bar",
		Github_slug: "bar",
	}
	teamBaz := configs.TeamConfig{
		Name:        "The team known as Baz",
		Github_slug: "baz",
	}
	// Project "foo" will have 3 owners
	fooOwners := mapset.NewSet[configs.TeamConfig]()
	fooOwners.Add(teamFoo)
	fooOwners.Add(teamBar)
	fooOwners.Add(teamBaz)
	testProjectFindings.Projects[0].Owners = fooOwners
	// Project "bar" will have 2 owners
	barOwners := mapset.NewSet[configs.TeamConfig]()
	barOwners.Add(teamBar)
	barOwners.Add(teamBaz)
	testProjectFindings.Projects[1].Owners = barOwners
	// Project "baz" will have 1 owner
	bazOwners := mapset.NewSet[configs.TeamConfig]()
	bazOwners.Add(teamBaz)
	testProjectFindings.Projects[2].Owners = bazOwners
	// Make sure to clear our ownership changes when the test is done
	defer func() {
		for _, proj := range testProjectFindings.Projects {
			proj.Owners = mapset.NewSet[configs.TeamConfig]()
		}
	}()
	projFooSummary := reporting.NewProjectFindingSummary(&projFoo)
	projBarSummary := reporting.NewProjectFindingSummary(&projBar)
	projBazSummary := reporting.NewProjectFindingSummary(&projBaz)

	teamFooSummary := reporting.NewProjectFindingSummary(querying.NewProject(reporting.SUMMARY_KEY))
	teamBarSummary := reporting.NewProjectFindingSummary(querying.NewProject(reporting.SUMMARY_KEY))
	teamBazSummary := reporting.NewProjectFindingSummary(querying.NewProject(reporting.SUMMARY_KEY))

	summaries := []reporting.ProjectFindingSummary{projFooSummary, projBarSummary, projBazSummary}

	expected := map[configs.TeamConfig]reporting.TeamProjectCollection{
		teamFoo: {&projFooSummary, &teamFooSummary},
		teamBar: {&projFooSummary, &projBarSummary, &teamBarSummary},
		teamBaz: {&projFooSummary, &projBarSummary, &projBazSummary, &teamBazSummary},
	}

	actual := reporting.GroupTeamFindings(&testProjectFindings, summaries)

	assert.Equal(t, expected, actual)
}
