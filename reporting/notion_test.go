package reporting_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/underdog-tech/vulnbot/configs"
	"github.com/underdog-tech/vulnbot/querying"
	"github.com/underdog-tech/vulnbot/reporting"
	"github.com/underdog-tech/vulnbot/test"
)

type MockNotionClient struct {
	mock.Mock
}

func (m *MockNotionClient) CreateDatabaseRow(
	databaseID string,
	properties map[string]interface{},
	blocks []map[string]interface{},
) (string, error) {
	args := m.Called(databaseID, properties, blocks)
	return args.String(0), args.Error(1)
}

func (m *MockNotionClient) ReplacePageContent(pageID string, blocks []map[string]interface{}) error {
	args := m.Called(pageID, blocks)
	return args.Error(0)
}

func (m *MockNotionClient) AppendBlockChildren(blockID string, blocks []map[string]interface{}) error {
	args := m.Called(blockID, blocks)
	return args.Error(0)
}

func (m *MockNotionClient) GetToggleBlockChildrenIDs(blockID string) ([]string, error) {
	args := m.Called(blockID)
	ids, _ := args.Get(0).([]string)
	return ids, args.Error(1)
}

func (m *MockNotionClient) QueryDatabaseTitles(databaseID string) (map[string]string, error) {
	args := m.Called(databaseID)
	titles, _ := args.Get(0).(map[string]string)
	return titles, args.Error(1)
}

func (m *MockNotionClient) UpdatePageProperties(pageID string, properties map[string]interface{}) error {
	args := m.Called(pageID, properties)
	return args.Error(0)
}

func (m *MockNotionClient) ArchivePage(pageID string) error {
	args := m.Called(pageID)
	return args.Error(0)
}

// stubNoopFindingAttachment makes attachSeverityFindings a harmless no-op
// for containerID: GetToggleBlockChildrenIDs returns an empty list, which
// mismatches whatever repo count the caller actually has, so
// attachSeverityFindings logs and returns without calling
// AppendBlockChildren at all. Used by tests that exercise
// CreateDatabaseRow/ReplacePageContent but don't care about the deeper
// finding-attachment behavior - without this, those calls would panic the
// mock (an unmocked method call).
func stubNoopFindingAttachment(mockClient *MockNotionClient, containerID string) {
	mockClient.On("GetToggleBlockChildrenIDs", containerID).Return([]string{}, nil).Maybe()
}

// blocksContain marshals a slice of Notion block maps to JSON and checks it
// for each of the given substrings, so tests can assert on rendered content
// without hand-parsing the block structure.
func blocksContain(t *testing.T, blocks []map[string]interface{}, substrings ...string) bool {
	t.Helper()
	raw, err := json.Marshal(blocks)
	if err != nil {
		return false
	}
	content := string(raw)
	for _, substr := range substrings {
		if !strings.Contains(content, substr) {
			return false
		}
	}
	return true
}

func TestNewNotionReporterRequiresAuthToken(t *testing.T) {
	_, err := reporting.NewNotionReporter(&configs.Config{
		Notion_database_id: "db-id",
	})
	assert.Error(t, err, "No Notion token was provided.")
}

func TestNewNotionReporterRequiresDatabaseID(t *testing.T) {
	_, err := reporting.NewNotionReporter(&configs.Config{
		Notion_auth_token: "notion-token",
	})
	assert.Error(t, err, "No Notion database ID was configured.")
}

func TestNewNotionReporterSucceeds(t *testing.T) {
	_, err := reporting.NewNotionReporter(&configs.Config{
		Notion_auth_token:  "notion-token",
		Notion_database_id: "db-id",
	})
	assert.NoError(t, err)
}

func TestSendNotionSummaryReportRefreshesPageOnly(t *testing.T) {
	mockClient := new(MockNotionClient)
	cfg := configs.Config{
		Notion_database_id:     "db-id",
		Notion_summary_page_id: "summary-page-id",
	}
	reporter := reporting.NotionReporter{Config: &cfg, Client: mockClient}
	report := reporting.NewFindingSummary()
	report.TotalCount = 42
	report.AffectedRepos = 3

	// The org-wide summary should only refresh the persistent page - it
	// should NOT write a row to the shared history database. That database
	// is for per-team rows only, so its "Team" property never needs a
	// sentinel value for an org-wide rollup.
	mockClient.On("ReplacePageContent", "summary-page-id", mock.Anything).Return(nil).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := reporter.SendSummaryReport("Foo", 5, report, test.TEST_REPORT_TIME, test.TEST_TEAM_SUMMARIES, wg)
	wg.Wait()

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
	mockClient.AssertNotCalled(t, "CreateDatabaseRow", mock.Anything, mock.Anything, mock.Anything)
}

func TestSendNotionSummaryReportDoesNothingWhenPageNotConfigured(t *testing.T) {
	mockClient := new(MockNotionClient)
	cfg := configs.Config{
		Notion_database_id: "db-id",
		// Notion_summary_page_id intentionally left blank.
	}
	reporter := reporting.NotionReporter{Config: &cfg, Client: mockClient}
	report := reporting.NewFindingSummary()

	// No calls of any kind are expected: no history row (summary reports
	// never write one), and no page refresh (none is configured).

	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := reporter.SendSummaryReport("Foo", 1, report, test.TEST_REPORT_TIME, test.TEST_TEAM_SUMMARIES, wg)
	wg.Wait()

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
	mockClient.AssertNotCalled(t, "CreateDatabaseRow", mock.Anything, mock.Anything, mock.Anything)
	mockClient.AssertNotCalled(t, "ReplacePageContent", mock.Anything, mock.Anything)
}

func TestSendNotionTeamReportContinuesAfterHistoryRowError(t *testing.T) {
	teamFoo := configs.TeamConfig{Name: "foo", Github_slug: "foo", Notion_page_id: "foo-page-id"}
	cfg := configs.Config{
		Notion_database_id: "db-id",
		Team:               []configs.TeamConfig{teamFoo},
	}
	mockClient := new(MockNotionClient)
	reporter := reporting.NotionReporter{Config: &cfg, Client: mockClient}

	repo1Report := reporting.NewProjectFindingSummary(querying.NewProject("repo1"))
	summaryReport := reporting.NewProjectFindingSummary(querying.NewProject(reporting.SUMMARY_KEY))
	teamReports := map[configs.TeamConfig]reporting.TeamProjectCollection{
		teamFoo: {&repo1Report, &summaryReport},
	}

	// The history row write fails, but the page refresh should still be
	// attempted - the two writes are independent of one another. Since the
	// row write fails, attachSeverityFindings is never invoked for it (no
	// page ID to look up children under); the page write succeeds, so it
	// gets the no-op stub.
	mockClient.On("CreateDatabaseRow", "db-id", mock.Anything, mock.Anything).
		Return("", fmt.Errorf("Notion API returned status 500")).Once()
	mockClient.On("ReplacePageContent", "foo-page-id", mock.Anything).Return(nil).Once()
	stubNoopFindingAttachment(mockClient, "foo-page-id")

	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := reporter.SendTeamReports(teamReports, test.TEST_REPORT_TIME, wg)
	wg.Wait()

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestSendNotionTeamReportsComputesAffectedReposCorrectly(t *testing.T) {
	// This reproduces the actual bug: GroupTeamFindings' synthetic summary
	// entry always has AffectedRepos == 0 (see comment at the
	// getTeamAffectedRepoCount call site), so this test deliberately builds
	// that same buggy shape and asserts the reporter doesn't trust it.
	teamFoo := configs.TeamConfig{Name: "foo", Github_slug: "foo"}
	cfg := configs.Config{Notion_database_id: "db-id", Team: []configs.TeamConfig{teamFoo}}
	mockClient := new(MockNotionClient)
	reporter := reporting.NotionReporter{Config: &cfg, Client: mockClient}

	repoWithFindings := reporting.NewProjectFindingSummary(querying.NewProject("repo-with-findings"))
	repoWithFindings.AffectedRepos = 1
	repoWithFindings.TotalCount = 5

	repoWithoutFindings := reporting.NewProjectFindingSummary(querying.NewProject("repo-without-findings"))
	// AffectedRepos and TotalCount are left at their zero values.

	summaryEntry := reporting.NewProjectFindingSummary(querying.NewProject(reporting.SUMMARY_KEY))
	summaryEntry.TotalCount = 5
	// summaryEntry.AffectedRepos is left at 0, matching real GroupTeamFindings output.

	teamReports := map[configs.TeamConfig]reporting.TeamProjectCollection{
		teamFoo: {&repoWithFindings, &repoWithoutFindings, &summaryEntry},
	}

	mockClient.On("CreateDatabaseRow", "db-id", mock.MatchedBy(func(properties map[string]interface{}) bool {
		affectedRepos, ok := properties["Affected Repos"].(map[string]interface{})
		if !ok {
			return false
		}
		count, ok := affectedRepos["number"].(int)
		return ok && count == 1 // one real repo has findings, despite summaryEntry.AffectedRepos == 0
	}), mock.Anything).Return("row-page-id", nil).Once()
	stubNoopFindingAttachment(mockClient, "row-page-id")

	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := reporter.SendTeamReports(teamReports, test.TEST_REPORT_TIME, wg)
	wg.Wait()

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestSendNotionTeamReportOmitsCleanReposFromRowButKeepsThemOnPage(t *testing.T) {
	teamFoo := configs.TeamConfig{Name: "foo", Github_slug: "foo", Notion_page_id: "foo-page-id"}
	cfg := configs.Config{Notion_database_id: "db-id", Team: []configs.TeamConfig{teamFoo}}
	mockClient := new(MockNotionClient)
	reporter := reporting.NotionReporter{Config: &cfg, Client: mockClient}

	dirtyProject := querying.NewProject("repo-with-findings")
	dirtyProject.Findings = append(dirtyProject.Findings, &querying.Finding{
		Severity: configs.FindingSeverityCritical, PackageName: "pkg",
	})
	dirtyRepo := reporting.NewProjectFindingSummary(dirtyProject)

	cleanProject := querying.NewProject("repo-with-no-findings")
	// cleanProject.Findings intentionally left empty.
	cleanRepo := reporting.NewProjectFindingSummary(cleanProject)

	summaryEntry := reporting.NewProjectFindingSummary(querying.NewProject(reporting.SUMMARY_KEY))

	teamReports := map[configs.TeamConfig]reporting.TeamProjectCollection{
		teamFoo: {&dirtyRepo, &cleanRepo, &summaryEntry},
	}

	// The history row should mention the dirty repo but never the clean one.
	mockClient.On("CreateDatabaseRow", "db-id", mock.Anything, mock.MatchedBy(func(blocks []map[string]interface{}) bool {
		return blocksContain(t, blocks, "repo-with-findings") &&
			!blocksContain(t, blocks, "repo-with-no-findings")
	})).Return("row-page-id", nil).Once()
	stubNoopFindingAttachment(mockClient, "row-page-id")

	// The persistent page should mention BOTH repos - it's a full roster.
	mockClient.On("ReplacePageContent", "foo-page-id", mock.MatchedBy(func(blocks []map[string]interface{}) bool {
		return blocksContain(t, blocks, "repo-with-findings", "repo-with-no-findings")
	})).Return(nil).Once()
	stubNoopFindingAttachment(mockClient, "foo-page-id")

	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := reporter.SendTeamReports(teamReports, test.TEST_REPORT_TIME, wg)
	wg.Wait()

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestSendNotionTeamReportsWritesRowAndPagePerTeam(t *testing.T) {
	teamFoo := configs.TeamConfig{Name: "foo", Github_slug: "foo", Notion_page_id: "foo-page-id"}
	teamBar := configs.TeamConfig{Name: "bar", Github_slug: "bar"} // no Notion_page_id

	cfg := configs.Config{
		Notion_database_id: "db-id",
		Team:               []configs.TeamConfig{teamFoo, teamBar},
	}
	mockClient := new(MockNotionClient)
	reporter := reporting.NotionReporter{Config: &cfg, Client: mockClient}

	repo1Report := reporting.NewProjectFindingSummary(querying.NewProject("repo1"))
	summaryReport := reporting.NewProjectFindingSummary(querying.NewProject(reporting.SUMMARY_KEY))
	teamReports := map[configs.TeamConfig]reporting.TeamProjectCollection{
		teamFoo: {&repo1Report, &summaryReport},
		teamBar: {&repo1Report, &summaryReport},
	}

	// Both teams get a history row...
	mockClient.On("CreateDatabaseRow", "db-id", mock.Anything, mock.Anything).Return("row-page-id", nil).Twice()
	stubNoopFindingAttachment(mockClient, "row-page-id")
	// ...but only the team with a configured Notion_page_id gets its page refreshed.
	mockClient.On("ReplacePageContent", "foo-page-id", mock.Anything).Return(nil).Once()
	stubNoopFindingAttachment(mockClient, "foo-page-id")

	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := reporter.SendTeamReports(teamReports, test.TEST_REPORT_TIME, wg)
	wg.Wait()

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestSendNotionReportsWithNoClient(t *testing.T) {
	cfg := configs.Config{Notion_database_id: "db-id"}
	// Create reporter instances with NO client - this should not panic.
	summaryReporter := reporting.NotionReporter{Config: &cfg}
	teamReporter := reporting.NotionReporter{Config: &cfg}

	wg := new(sync.WaitGroup)
	wg.Add(2)
	_ = summaryReporter.SendSummaryReport(
		"Foo", 1, reporting.NewFindingSummary(), test.TEST_REPORT_TIME, test.TEST_TEAM_SUMMARIES, wg,
	)
	_ = teamReporter.SendTeamReports(test.TEST_TEAM_SUMMARIES, test.TEST_REPORT_TIME, wg)
	wg.Wait()
}

func TestSendNotionTeamReportLinksRepoNameToItsURL(t *testing.T) {
	teamFoo := configs.TeamConfig{Name: "foo", Github_slug: "foo"}
	cfg := configs.Config{Notion_database_id: "db-id", Team: []configs.TeamConfig{teamFoo}}
	mockClient := new(MockNotionClient)
	reporter := reporting.NotionReporter{Config: &cfg, Client: mockClient}

	project := querying.NewProject("repo1")
	project.Link = "https://github.com/some-org/repo1"
	repoReport := reporting.NewProjectFindingSummary(project)
	summaryEntry := reporting.NewProjectFindingSummary(querying.NewProject(reporting.SUMMARY_KEY))

	teamReports := map[configs.TeamConfig]reporting.TeamProjectCollection{
		teamFoo: {&repoReport, &summaryEntry},
	}

	// The repo name link lives in the repo toggle's own title, which IS
	// part of the initial CreateDatabaseRow blocks (only the findings
	// nested three levels down get attached in a later pass).
	mockClient.On("CreateDatabaseRow", "db-id", mock.Anything, mock.MatchedBy(func(blocks []map[string]interface{}) bool {
		return blocksContain(t, blocks, `"content":"repo1"`, `"link":{"url":"https://github.com/some-org/repo1"}`)
	})).Return("row-page-id", nil).Once()
	stubNoopFindingAttachment(mockClient, "row-page-id")

	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := reporter.SendTeamReports(teamReports, test.TEST_REPORT_TIME, wg)
	wg.Wait()

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestSendNotionTeamReportFallsBackToPlainTextWhenRepoHasNoLink(t *testing.T) {
	teamFoo := configs.TeamConfig{Name: "foo", Github_slug: "foo"}
	cfg := configs.Config{Notion_database_id: "db-id", Team: []configs.TeamConfig{teamFoo}}
	mockClient := new(MockNotionClient)
	reporter := reporting.NotionReporter{Config: &cfg, Client: mockClient}

	project := querying.NewProject("repo1")
	// project.Link intentionally left blank.
	repoReport := reporting.NewProjectFindingSummary(project)
	summaryEntry := reporting.NewProjectFindingSummary(querying.NewProject(reporting.SUMMARY_KEY))

	teamReports := map[configs.TeamConfig]reporting.TeamProjectCollection{
		teamFoo: {&repoReport, &summaryEntry},
	}

	mockClient.On("CreateDatabaseRow", "db-id", mock.Anything, mock.MatchedBy(func(blocks []map[string]interface{}) bool {
		// No "link" key should appear anywhere - never send Notion a link
		// object with an empty URL.
		raw, err := json.Marshal(blocks)
		if err != nil {
			return false
		}
		return !strings.Contains(string(raw), `"link"`)
	})).Return("row-page-id", nil).Once()
	stubNoopFindingAttachment(mockClient, "row-page-id")

	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := reporter.SendTeamReports(teamReports, test.TEST_REPORT_TIME, wg)
	wg.Wait()

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestNotionRepoToggleGroupsSeverityTogglesInOrder(t *testing.T) {
	// Severity ordering is now expressed structurally, as separate
	// toggles created in GetSeverityReportOrder()'s order, rather than as
	// a sort within one flat list - so this checks the ORDER the severity
	// toggle titles appear in, in the initial CreateDatabaseRow blocks
	// (the toggles themselves are level-2 content, created up front; only
	// their finding-bullet children are attached in a later pass).
	teamFoo := configs.TeamConfig{Name: "foo", Github_slug: "foo"}
	cfg := configs.Config{Notion_database_id: "db-id", Team: []configs.TeamConfig{teamFoo}}
	mockClient := new(MockNotionClient)
	reporter := reporting.NotionReporter{Config: &cfg, Client: mockClient}

	project := querying.NewProject("repo1")
	project.Findings = append(project.Findings,
		&querying.Finding{Severity: configs.FindingSeverityLow, PackageName: "pkg"},
		&querying.Finding{Severity: configs.FindingSeverityCritical, PackageName: "pkg"},
		&querying.Finding{Severity: configs.FindingSeverityModerate, PackageName: "pkg"},
		&querying.Finding{Severity: configs.FindingSeverityHigh, PackageName: "pkg"},
	)
	repoReport := reporting.NewProjectFindingSummary(project)
	summaryEntry := reporting.NewProjectFindingSummary(querying.NewProject(reporting.SUMMARY_KEY))

	teamReports := map[configs.TeamConfig]reporting.TeamProjectCollection{
		teamFoo: {&repoReport, &summaryEntry},
	}

	mockClient.On("CreateDatabaseRow", "db-id", mock.Anything, mock.MatchedBy(func(blocks []map[string]interface{}) bool {
		raw, err := json.Marshal(blocks)
		if err != nil {
			return false
		}
		content := string(raw)
		critIdx := strings.Index(content, "Critical (1)")
		highIdx := strings.Index(content, "High (1)")
		modIdx := strings.Index(content, "Moderate (1)")
		lowIdx := strings.Index(content, "Low (1)")
		return critIdx >= 0 && highIdx >= 0 && modIdx >= 0 && lowIdx >= 0 &&
			critIdx < highIdx && highIdx < modIdx && modIdx < lowIdx
	})).Return("row-page-id", nil).Once()
	stubNoopFindingAttachment(mockClient, "row-page-id")

	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := reporter.SendTeamReports(teamReports, test.TEST_REPORT_TIME, wg)
	wg.Wait()

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestNotionAttachSeverityFindingsWiresFindingsIntoTheRightToggle(t *testing.T) {
	// End-to-end (against the mock) check of the full three-step dance:
	// create repo+severity toggles, look up their real IDs, attach each
	// severity's findings into the matching toggle.
	teamFoo := configs.TeamConfig{Name: "foo", Github_slug: "foo"}
	cfg := configs.Config{Notion_database_id: "db-id", Team: []configs.TeamConfig{teamFoo}}
	mockClient := new(MockNotionClient)
	reporter := reporting.NotionReporter{Config: &cfg, Client: mockClient}

	project := querying.NewProject("repo1")
	project.Findings = append(project.Findings,
		&querying.Finding{
			Identifiers: querying.FindingIdentifierMap{querying.FindingIdentifierCVE: "CVE-CRITICAL"},
			Severity:    configs.FindingSeverityCritical, PackageName: "pkg-a",
		},
		&querying.Finding{
			Identifiers: querying.FindingIdentifierMap{querying.FindingIdentifierCVE: "CVE-LOW"},
			Severity:    configs.FindingSeverityLow, PackageName: "pkg-b",
		},
	)
	repoReport := reporting.NewProjectFindingSummary(project)
	summaryEntry := reporting.NewProjectFindingSummary(querying.NewProject(reporting.SUMMARY_KEY))

	teamReports := map[configs.TeamConfig]reporting.TeamProjectCollection{
		teamFoo: {&repoReport, &summaryEntry},
	}

	mockClient.On("CreateDatabaseRow", "db-id", mock.Anything, mock.Anything).
		Return("row-page-id", nil).Once()

	// Walk the three levels exactly as attachSeverityFindings should:
	// row page -> one repo toggle -> two severity toggles (Critical, Low,
	// in that order, matching GetSeverityReportOrder()).
	mockClient.On("GetToggleBlockChildrenIDs", "row-page-id").
		Return([]string{"repo-toggle-id"}, nil).Once()
	mockClient.On("GetToggleBlockChildrenIDs", "repo-toggle-id").
		Return([]string{"critical-toggle-id", "low-toggle-id"}, nil).Once()

	mockClient.On("AppendBlockChildren", "critical-toggle-id", mock.MatchedBy(func(blocks []map[string]interface{}) bool {
		return blocksContain(t, blocks, "CVE-CRITICAL", "pkg-a") && !blocksContain(t, blocks, "CVE-LOW")
	})).Return(nil).Once()
	mockClient.On("AppendBlockChildren", "low-toggle-id", mock.MatchedBy(func(blocks []map[string]interface{}) bool {
		return blocksContain(t, blocks, "CVE-LOW", "pkg-b") && !blocksContain(t, blocks, "CVE-CRITICAL")
	})).Return(nil).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := reporter.SendTeamReports(teamReports, test.TEST_REPORT_TIME, wg)
	wg.Wait()

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestNotionAttachSeverityFindingsSkipsRepoOnToggleCountMismatch(t *testing.T) {
	// If Notion ever reports a different number of severity toggles than
	// expected for a repo, that repo's findings should be skipped (logged,
	// not attached to what might be the wrong toggle) - not panic, not
	// attach to a guessed ID.
	teamFoo := configs.TeamConfig{Name: "foo", Github_slug: "foo"}
	cfg := configs.Config{Notion_database_id: "db-id", Team: []configs.TeamConfig{teamFoo}}
	mockClient := new(MockNotionClient)
	reporter := reporting.NotionReporter{Config: &cfg, Client: mockClient}

	project := querying.NewProject("repo1")
	project.Findings = append(project.Findings,
		&querying.Finding{Severity: configs.FindingSeverityCritical, PackageName: "pkg-a"},
		&querying.Finding{Severity: configs.FindingSeverityLow, PackageName: "pkg-b"},
	)
	repoReport := reporting.NewProjectFindingSummary(project)
	summaryEntry := reporting.NewProjectFindingSummary(querying.NewProject(reporting.SUMMARY_KEY))

	teamReports := map[configs.TeamConfig]reporting.TeamProjectCollection{
		teamFoo: {&repoReport, &summaryEntry},
	}

	mockClient.On("CreateDatabaseRow", "db-id", mock.Anything, mock.Anything).
		Return("row-page-id", nil).Once()
	mockClient.On("GetToggleBlockChildrenIDs", "row-page-id").
		Return([]string{"repo-toggle-id"}, nil).Once()
	// Only one severity toggle reported back, but two groups (Critical,
	// Low) actually exist - a mismatch.
	mockClient.On("GetToggleBlockChildrenIDs", "repo-toggle-id").
		Return([]string{"only-one-toggle-id"}, nil).Once()
	// AppendBlockChildren must NOT be called at all for this repo.

	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := reporter.SendTeamReports(teamReports, test.TEST_REPORT_TIME, wg)
	wg.Wait()

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
	mockClient.AssertNotCalled(t, "AppendBlockChildren", mock.Anything, mock.Anything)
}

func TestSendNotionTeamReportLinksCVEToNVD(t *testing.T) {
	teamFoo := configs.TeamConfig{Name: "foo", Github_slug: "foo"}
	cfg := configs.Config{Notion_database_id: "db-id", Team: []configs.TeamConfig{teamFoo}}
	mockClient := new(MockNotionClient)
	reporter := reporting.NotionReporter{Config: &cfg, Client: mockClient}

	project := querying.NewProject("repo1")
	project.Findings = append(project.Findings, &querying.Finding{
		Identifiers: querying.FindingIdentifierMap{querying.FindingIdentifierCVE: "CVE-2024-9999"},
		Severity:    configs.FindingSeverityCritical,
		PackageName: "left-pad",
	})
	repoReport := reporting.NewProjectFindingSummary(project)
	summaryEntry := reporting.NewProjectFindingSummary(querying.NewProject(reporting.SUMMARY_KEY))

	teamReports := map[configs.TeamConfig]reporting.TeamProjectCollection{
		teamFoo: {&repoReport, &summaryEntry},
	}

	mockClient.On("CreateDatabaseRow", "db-id", mock.Anything, mock.Anything).
		Return("row-page-id", nil).Once()
	mockClient.On("GetToggleBlockChildrenIDs", "row-page-id").
		Return([]string{"repo-toggle-id"}, nil).Once()
	mockClient.On("GetToggleBlockChildrenIDs", "repo-toggle-id").
		Return([]string{"critical-toggle-id"}, nil).Once()

	// The CVE link now appears in the AppendBlockChildren call, since
	// finding bullets are third-level content attached after the fact.
	mockClient.On("AppendBlockChildren", "critical-toggle-id", mock.MatchedBy(func(blocks []map[string]interface{}) bool {
		return blocksContain(t, blocks,
			`"content":"CVE-2024-9999"`,
			`"link":{"url":"https://nvd.nist.gov/vuln/detail/CVE-2024-9999"}`,
		)
	})).Return(nil).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := reporter.SendTeamReports(teamReports, test.TEST_REPORT_TIME, wg)
	wg.Wait()

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestSendNotionTeamReportKeepsGHSAPlainAndCVELinked(t *testing.T) {
	teamFoo := configs.TeamConfig{Name: "foo", Github_slug: "foo"}
	cfg := configs.Config{Notion_database_id: "db-id", Team: []configs.TeamConfig{teamFoo}}
	mockClient := new(MockNotionClient)
	reporter := reporting.NotionReporter{Config: &cfg, Client: mockClient}

	project := querying.NewProject("repo1")
	project.Findings = append(project.Findings, &querying.Finding{
		Identifiers: querying.FindingIdentifierMap{
			querying.FindingIdentifierCVE:  "CVE-2024-1111",
			querying.FindingIdentifierGHSA: "GHSA-aaaa-bbbb-cccc",
		},
		Severity:    configs.FindingSeverityHigh,
		PackageName: "some-package",
	})
	repoReport := reporting.NewProjectFindingSummary(project)
	summaryEntry := reporting.NewProjectFindingSummary(querying.NewProject(reporting.SUMMARY_KEY))

	teamReports := map[configs.TeamConfig]reporting.TeamProjectCollection{
		teamFoo: {&repoReport, &summaryEntry},
	}

	mockClient.On("CreateDatabaseRow", "db-id", mock.Anything, mock.Anything).
		Return("row-page-id", nil).Once()
	mockClient.On("GetToggleBlockChildrenIDs", "row-page-id").
		Return([]string{"repo-toggle-id"}, nil).Once()
	mockClient.On("GetToggleBlockChildrenIDs", "repo-toggle-id").
		Return([]string{"high-toggle-id"}, nil).Once()

	mockClient.On("AppendBlockChildren", "high-toggle-id", mock.MatchedBy(func(blocks []map[string]interface{}) bool {
		raw, err := json.Marshal(blocks)
		if err != nil {
			return false
		}
		content := string(raw)
		hasCVELink := strings.Contains(content, `"link":{"url":"https://nvd.nist.gov/vuln/detail/CVE-2024-1111"}`)
		hasGHSAText := strings.Contains(content, `"content":"GHSA-aaaa-bbbb-cccc"`)
		// The GHSA span itself shouldn't carry a link - only the CVE's
		// span should, so exactly one "link" key should appear at all.
		linkCount := strings.Count(content, `"link"`)
		return hasCVELink && hasGHSAText && linkCount == 1
	})).Return(nil).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := reporter.SendTeamReports(teamReports, test.TEST_REPORT_TIME, wg)
	wg.Wait()

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestSendNotionTeamHistoryRowTruncatesOverflowFindingsWithinASeverityTier(t *testing.T) {
	// A single severity tier with more than 100 findings for one repo
	// shouldn't crash the whole attachment step - it should truncate that
	// tier's finding list with a note. (Truncation is per-severity-tier
	// now, not per-repo overall, since each tier is its own `children`
	// array with its own 100-element cap.)
	teamFoo := configs.TeamConfig{Name: "foo", Github_slug: "foo"}
	cfg := configs.Config{Notion_database_id: "db-id", Team: []configs.TeamConfig{teamFoo}}
	mockClient := new(MockNotionClient)
	reporter := reporting.NotionReporter{Config: &cfg, Client: mockClient}

	project := querying.NewProject("repo-with-many-findings")
	for i := 0; i < 150; i++ {
		project.Findings = append(project.Findings, &querying.Finding{
			Identifiers: querying.FindingIdentifierMap{querying.FindingIdentifierCVE: fmt.Sprintf("CVE-2024-%d", i)},
			Severity:    configs.FindingSeverityLow,
			PackageName: "some-package",
		})
	}
	repoReport := reporting.NewProjectFindingSummary(project)
	summaryEntry := reporting.NewProjectFindingSummary(querying.NewProject(reporting.SUMMARY_KEY))

	teamReports := map[configs.TeamConfig]reporting.TeamProjectCollection{
		teamFoo: {&repoReport, &summaryEntry},
	}

	mockClient.On("CreateDatabaseRow", "db-id", mock.Anything, mock.Anything).
		Return("row-page-id", nil).Once()
	mockClient.On("GetToggleBlockChildrenIDs", "row-page-id").
		Return([]string{"repo-toggle-id"}, nil).Once()
	mockClient.On("GetToggleBlockChildrenIDs", "repo-toggle-id").
		Return([]string{"low-toggle-id"}, nil).Once()

	mockClient.On("AppendBlockChildren", "low-toggle-id", mock.MatchedBy(func(blocks []map[string]interface{}) bool {
		return blocksContain(t, blocks, "more findings not shown here")
	})).Return(nil).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := reporter.SendTeamReports(teamReports, test.TEST_REPORT_TIME, wg)
	wg.Wait()

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestSendRepoOwnershipReportSkipsWhenNotConfigured(t *testing.T) {
	mockClient := new(MockNotionClient)
	cfg := configs.Config{Notion_database_id: "db-id"} // Notion_ownership_database_id intentionally blank
	reporter := reporting.NotionReporter{Config: &cfg, Client: mockClient}

	// No calls of any kind expected.
	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := reporter.SendRepoOwnershipReport([]*querying.Project{querying.NewProject("repo1")}, wg)
	wg.Wait()

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestSendRepoOwnershipReportCreatesRowsForNewRepos(t *testing.T) {
	cfg := configs.Config{Notion_ownership_database_id: "ownership-db-id"}
	mockClient := new(MockNotionClient)
	reporter := reporting.NotionReporter{Config: &cfg, Client: mockClient}

	ownedProject := querying.NewProject("owned-repo")
	ownedProject.Owners.Add(configs.TeamConfig{Name: "Team Foo"})

	unownedProject := querying.NewProject("unowned-repo")
	// No owners added.

	mockClient.On("QueryDatabaseTitles", "ownership-db-id").Return(map[string]string{}, nil).Once()

	mockClient.On("CreateDatabaseRow", "ownership-db-id", mock.MatchedBy(func(properties map[string]interface{}) bool {
		return blocksContain(t, []map[string]interface{}{properties}, `"content":"owned-repo"`, `"name":"Team Foo"`)
	}), mock.Anything).Return("page-1", nil).Once()

	mockClient.On("CreateDatabaseRow", "ownership-db-id", mock.MatchedBy(func(properties map[string]interface{}) bool {
		return blocksContain(t, []map[string]interface{}{properties}, `"content":"unowned-repo"`, `"name":"Unowned"`)
	}), mock.Anything).Return("page-2", nil).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := reporter.SendRepoOwnershipReport([]*querying.Project{ownedProject, unownedProject}, wg)
	wg.Wait()

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestSendRepoOwnershipReportUpdatesExistingRowsInPlace(t *testing.T) {
	cfg := configs.Config{Notion_ownership_database_id: "ownership-db-id"}
	mockClient := new(MockNotionClient)
	reporter := reporting.NotionReporter{Config: &cfg, Client: mockClient}

	project := querying.NewProject("existing-repo")
	project.Owners.Add(configs.TeamConfig{Name: "Team Foo"})

	mockClient.On("QueryDatabaseTitles", "ownership-db-id").
		Return(map[string]string{"existing-repo": "existing-page-id"}, nil).Once()

	mockClient.On("UpdatePageProperties", "existing-page-id", mock.MatchedBy(func(properties map[string]interface{}) bool {
		return blocksContain(t, []map[string]interface{}{properties}, `"name":"Team Foo"`)
	})).Return(nil).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := reporter.SendRepoOwnershipReport([]*querying.Project{project}, wg)
	wg.Wait()

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
	mockClient.AssertNotCalled(t, "CreateDatabaseRow", mock.Anything, mock.Anything, mock.Anything)
}

func TestSendRepoOwnershipReportArchivesStaleRows(t *testing.T) {
	cfg := configs.Config{Notion_ownership_database_id: "ownership-db-id"}
	mockClient := new(MockNotionClient)
	reporter := reporting.NotionReporter{Config: &cfg, Client: mockClient}

	// "gone-repo" existed last run but isn't in this run's project list at
	// all (archived, renamed, or deleted since) - its row should be
	// archived. "still-here-repo" is in both and should just be updated.
	stillHereProject := querying.NewProject("still-here-repo")

	mockClient.On("QueryDatabaseTitles", "ownership-db-id").Return(map[string]string{
		"still-here-repo": "still-here-page-id",
		"gone-repo":       "gone-page-id",
	}, nil).Once()

	mockClient.On("UpdatePageProperties", "still-here-page-id", mock.Anything).Return(nil).Once()
	mockClient.On("ArchivePage", "gone-page-id").Return(nil).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := reporter.SendRepoOwnershipReport([]*querying.Project{stillHereProject}, wg)
	wg.Wait()

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
	mockClient.AssertNotCalled(t, "ArchivePage", "still-here-page-id")
}

func TestSendRepoOwnershipReportListsMultipleOwningTeams(t *testing.T) {
	cfg := configs.Config{Notion_ownership_database_id: "ownership-db-id"}
	mockClient := new(MockNotionClient)
	reporter := reporting.NotionReporter{Config: &cfg, Client: mockClient}

	project := querying.NewProject("shared-repo")
	project.Owners.Add(configs.TeamConfig{Name: "Team Foo"})
	project.Owners.Add(configs.TeamConfig{Name: "Team Bar"})

	mockClient.On("QueryDatabaseTitles", "ownership-db-id").Return(map[string]string{}, nil).Once()

	mockClient.On("CreateDatabaseRow", "ownership-db-id", mock.MatchedBy(func(properties map[string]interface{}) bool {
		return blocksContain(t, []map[string]interface{}{properties}, `"name":"Team Bar"`, `"name":"Team Foo"`)
	}), mock.Anything).Return("page-1", nil).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := reporter.SendRepoOwnershipReport([]*querying.Project{project}, wg)
	wg.Wait()

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestSendRepoOwnershipReportLinksToPlainRepoURLNotSecurityPage(t *testing.T) {
	cfg := configs.Config{Notion_ownership_database_id: "ownership-db-id"}
	mockClient := new(MockNotionClient)
	reporter := reporting.NotionReporter{Config: &cfg, Client: mockClient}

	// Every known DataSource sets Project.Link to "<repo URL>/security"
	// (see querying/github.go and querying/codeql.go) - the ownership
	// registry should link to the plain repo URL instead, since that
	// security page requires Admin/Maintain access most people won't have.
	project := querying.NewProject("some-repo")
	project.Link = "https://github.com/some-org/some-repo/security"

	mockClient.On("QueryDatabaseTitles", "ownership-db-id").Return(map[string]string{}, nil).Once()

	mockClient.On("CreateDatabaseRow", "ownership-db-id", mock.MatchedBy(func(properties map[string]interface{}) bool {
		content := []map[string]interface{}{properties}
		hasPlainURL := blocksContain(t, content, `"link":{"url":"https://github.com/some-org/some-repo"}`)
		hasSecurityURL := blocksContain(t, content, "some-repo/security")
		return hasPlainURL && !hasSecurityURL
	}), mock.Anything).Return("page-1", nil).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := reporter.SendRepoOwnershipReport([]*querying.Project{project}, wg)
	wg.Wait()

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestSendRepoOwnershipReportSetsVisibilityAndForkStatus(t *testing.T) {
	cfg := configs.Config{Notion_ownership_database_id: "ownership-db-id"}
	mockClient := new(MockNotionClient)
	reporter := reporting.NotionReporter{Config: &cfg, Client: mockClient}

	publicFork := querying.NewProject("public-fork")
	publicFork.IsFork = true
	publicFork.Visibility = "PUBLIC"

	privateNonFork := querying.NewProject("private-repo")
	privateNonFork.IsFork = false
	privateNonFork.Visibility = "PRIVATE"

	mockClient.On("QueryDatabaseTitles", "ownership-db-id").Return(map[string]string{}, nil).Once()

	mockClient.On("CreateDatabaseRow", "ownership-db-id", mock.MatchedBy(func(properties map[string]interface{}) bool {
		content := []map[string]interface{}{properties}
		return blocksContain(t, content, `"content":"public-fork"`) &&
			blocksContain(t, content, `"select":{"name":"Public"}`) &&
			blocksContain(t, content, `"checkbox":true`)
	}), mock.Anything).Return("page-1", nil).Once()

	mockClient.On("CreateDatabaseRow", "ownership-db-id", mock.MatchedBy(func(properties map[string]interface{}) bool {
		content := []map[string]interface{}{properties}
		return blocksContain(t, content, `"content":"private-repo"`) &&
			blocksContain(t, content, `"select":{"name":"Private"}`) &&
			blocksContain(t, content, `"checkbox":false`)
	}), mock.Anything).Return("page-2", nil).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := reporter.SendRepoOwnershipReport([]*querying.Project{publicFork, privateNonFork}, wg)
	wg.Wait()

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestSendRepoOwnershipReportLabelsUnknownVisibility(t *testing.T) {
	cfg := configs.Config{Notion_ownership_database_id: "ownership-db-id"}
	mockClient := new(MockNotionClient)
	reporter := reporting.NotionReporter{Config: &cfg, Client: mockClient}

	// Visibility left at its zero value ("") - e.g. a repo that somehow
	// never got a visibility value populated. Should show a real label,
	// not a blank/invalid select option.
	project := querying.NewProject("mystery-repo")

	mockClient.On("QueryDatabaseTitles", "ownership-db-id").Return(map[string]string{}, nil).Once()

	mockClient.On("CreateDatabaseRow", "ownership-db-id", mock.MatchedBy(func(properties map[string]interface{}) bool {
		return blocksContain(t, []map[string]interface{}{properties}, `"select":{"name":"Unknown"}`)
	}), mock.Anything).Return("page-1", nil).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := reporter.SendRepoOwnershipReport([]*querying.Project{project}, wg)
	wg.Wait()

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestSendNotionSummaryReportOmitsSlackFormattedHeader(t *testing.T) {
	// The header string built in internal/scan.go is Slack markup
	// (":robot_face: Vulnbot Summary Report :robot_face:") that Slack
	// renders as an emoji but Notion just shows as literal text. Notion's
	// persistent summary page shouldn't include it at all - it's passed
	// through the shared Reporter interface but deliberately unused here.
	mockClient := new(MockNotionClient)
	cfg := configs.Config{
		Notion_database_id:     "db-id",
		Notion_summary_page_id: "summary-page-id",
	}
	reporter := reporting.NotionReporter{Config: &cfg, Client: mockClient}
	report := reporting.NewFindingSummary()

	mockClient.On("ReplacePageContent", "summary-page-id", mock.MatchedBy(func(blocks []map[string]interface{}) bool {
		return !blocksContain(t, blocks, "robot_face") && !blocksContain(t, blocks, "Vulnbot Summary Report")
	})).Return(nil).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := reporter.SendSummaryReport(
		":robot_face: Vulnbot Summary Report :robot_face:", 1, report, test.TEST_REPORT_TIME, test.TEST_TEAM_SUMMARIES, wg,
	)
	wg.Wait()

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}