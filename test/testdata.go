package test

import (
	"time"

	"github.com/underdog-tech/vulnbot/configs"
	"github.com/underdog-tech/vulnbot/querying"
	"github.com/underdog-tech/vulnbot/reporting"
)

var (
	TEST_REPORT_TIME                  = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	TEST_REPORT_TIME_FORMATTED string = TEST_REPORT_TIME.Format(reporting.DATE_LAYOUT)

	TEST_FINDING_SUMMARY_FOO = reporting.FindingSummary{
		AffectedRepos:    0,
		TotalCount:       0,
		VulnsByEcosystem: map[configs.FindingEcosystemType]int{},
		VulnsBySeverity: map[configs.FindingSeverityType]int{
			configs.FindingSeverityCritical: 0,
			configs.FindingSeverityHigh:     0,
			configs.FindingSeverityModerate: 0,
			configs.FindingSeverityLow:      0,
		},
	}
	TEST_FINDING_SUMMARY_BAR = reporting.FindingSummary{
		AffectedRepos:    0,
		TotalCount:       10,
		VulnsByEcosystem: map[configs.FindingEcosystemType]int{},
		VulnsBySeverity: map[configs.FindingSeverityType]int{
			configs.FindingSeverityCritical: 1,
			configs.FindingSeverityHigh:     2,
			configs.FindingSeverityModerate: 3,
			configs.FindingSeverityLow:      4,
		},
	}

	TEST_PROJ_FOO = querying.Project{
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
	TEST_PROJ_BAR = querying.Project{
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
	TEST_SUMMARY = querying.Project{
		Name: reporting.SUMMARY_KEY,
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

	TEST_TEAM_FOO = configs.TeamConfig{
		Name:        "Team Foo",
		Github_slug: "foo",
	}
	TEST_TEAM_BAR = configs.TeamConfig{
		Name:        "Team Bar",
		Github_slug: "bar",
	}

	TEST_PROJ_FOO_SUMMARRY = reporting.ProjectFindingSummary{Project: &TEST_PROJ_FOO, FindingSummary: TEST_FINDING_SUMMARY_FOO}
	TEST_PROJ_BAR_SUMMARY  = reporting.ProjectFindingSummary{Project: &TEST_PROJ_BAR, FindingSummary: TEST_FINDING_SUMMARY_BAR}

	TEST_TEAM_FOO_SUMMARY = reporting.ProjectFindingSummary{Project: &TEST_SUMMARY, FindingSummary: TEST_FINDING_SUMMARY_FOO}
	TEST_TEAM_BAR_SUMMARY = reporting.ProjectFindingSummary{Project: &TEST_SUMMARY, FindingSummary: TEST_FINDING_SUMMARY_BAR}

	TEST_TEAM_SUMMARIES = map[configs.TeamConfig]reporting.TeamProjectCollection{
		TEST_TEAM_FOO: {&TEST_PROJ_FOO_SUMMARRY, &TEST_TEAM_FOO_SUMMARY},
		TEST_TEAM_BAR: {&TEST_PROJ_BAR_SUMMARY, &TEST_TEAM_BAR_SUMMARY},
	}
)
