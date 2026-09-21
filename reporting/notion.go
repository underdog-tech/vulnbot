package reporting

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/maps"

	"github.com/underdog-tech/vulnbot/configs"
	"github.com/underdog-tech/vulnbot/logger"
	"github.com/underdog-tech/vulnbot/querying"
)

const (
	// NOTION_API_BASE is the base URL for the Notion REST API.
	NOTION_API_BASE = "https://api.notion.com/v1"

	// NOTION_API_VERSION is pinned deliberately. This version predates
	// Notion's multi-source-database "data source" model, so a page's
	// parent is addressed directly by `database_id`. Since the shared
	// history database is a normal, single-source database (see setup
	// docs), this is safe and avoids depending on data-source lookups.
	NOTION_API_VERSION = "2022-06-28"

	// notionMaxBlocksPerRequest is the maximum number of blocks Notion
	// accepts in a single append-block-children request.
	notionMaxBlocksPerRequest = 100

	// notionMaxNestedChildren mirrors the same 100-element cap, but for a
	// single nested `children` array embedded inside one block (e.g. a
	// toggle's finding list) - see notionFindingBlocks. Kept one lower to
	// always leave room for a truncation notice.
	notionMaxNestedChildren = 100

	// notionMaxDescriptionLength truncates a finding's description before
	// rendering it, to keep individual vulnerability entries scannable and
	// comfortably under Notion's 2000-char-per-rich-text-object limit.
	notionMaxDescriptionLength = 500

	// notionPageTimestampLayout is used for the "generated at" line on the
	// persistent summary and team pages, in place of the shared
	// reporting.DATE_LAYOUT ("January 2, 2006") - deliberately kept
	// separate rather than changing the shared constant, since that's also
	// used by Console/Slack output this shouldn't affect. Includes both
	// time and a zone abbreviation, since reportTime is always UTC (see
	// internal/scan.go), so a viewer can tell not just which day a page
	// was last refreshed, but roughly when.
	notionPageTimestampLayout = "January 2, 2006 at 3:04 PM MST"
)

// notionSeverityColors maps each finding severity to the nearest available
// Notion callout block color. Notion's block color property only accepts a
// fixed set of named values, so this can't reuse the hex values from
// configs.GetConsoleSeverityColors() directly.
var notionSeverityColors = map[configs.FindingSeverityType]string{
	configs.FindingSeverityCritical:  "red_background",
	configs.FindingSeverityHigh:      "orange_background",
	configs.FindingSeverityModerate:  "yellow_background",
	configs.FindingSeverityLow:       "blue_background",
	configs.FindingSeverityInfo:      "blue_background",
	configs.FindingSeverityUndefined: "gray_background",
}

func getNotionColorForSeverity(severity configs.FindingSeverityType) string {
	color, exists := notionSeverityColors[severity]
	if !exists {
		return "gray_background"
	}
	return color
}

// getTeamAffectedRepoCount counts how many of a team's real repos (i.e.
// excluding the synthetic SUMMARY_KEY entry GroupTeamFindings appends) have
// at least one finding. This can't be read directly off
// TeamProjectCollection.GetTeamSummaryReport().AffectedRepos - see the
// comment at its call site in SendTeamReports for why.
func getTeamAffectedRepoCount(repos TeamProjectCollection) int {
	count := 0
	for _, repo := range repos {
		if repo.Project.Name == SUMMARY_KEY {
			continue
		}
		count += repo.AffectedRepos
	}
	return count
}

// NotionClientInterface wraps only the Notion operations NotionReporter
// needs, mirroring how SlackClientInterface in slack.go only exposes
// PostMessage. This keeps the surface small and lets tests inject a mock
// without making real HTTP calls.
type NotionClientInterface interface {
	// CreateDatabaseRow adds a new page (row) to the given database, with
	// the given page properties and, optionally, initial body content (up
	// to Notion's own two-level nesting limit per request - see
	// notionRepoToggleBlock). Pass a nil or empty blocks slice for a row
	// with no body content. Returns the new page's ID, since deeper
	// content (e.g. finding bullets under a severity toggle) may need to
	// be attached afterward via AppendBlockChildren.
	CreateDatabaseRow(databaseID string, properties map[string]interface{}, blocks []map[string]interface{}) (pageID string, err error)
	// ReplacePageContent fully overwrites a page's block content: it
	// deletes all of the page's existing children blocks, then appends the
	// given ones in their place.
	ReplacePageContent(pageID string, blocks []map[string]interface{}) error
	// AppendBlockChildren appends more blocks under an existing block
	// (such as a toggle created by CreateDatabaseRow or
	// ReplacePageContent), for content that couldn't be embedded in the
	// original request because it would exceed Notion's two-level nesting
	// limit per request.
	AppendBlockChildren(blockID string, blocks []map[string]interface{}) error
	// GetToggleBlockChildrenIDs returns the IDs of a block's direct
	// children that are themselves toggle blocks, in creation order. Used
	// to discover the real IDs Notion assigned to toggles that were just
	// created nested inside another block, so their own children (a third
	// level of nesting) can be attached in a follow-up call - see
	// attachSeverityFindings.
	GetToggleBlockChildrenIDs(blockID string) ([]string, error)
	// QueryDatabaseTitles returns every existing row in a database as a
	// map of its title (read from whichever property is actually the
	// title type, not assumed to be named "Name") to its page ID. Used to
	// sync a live-snapshot database (see SendRepoOwnershipReport) against
	// current reality without tracking state between runs ourselves.
	QueryDatabaseTitles(databaseID string) (map[string]string, error)
	// UpdatePageProperties overwrites the given properties on an existing
	// page, leaving its body content and any properties not mentioned
	// untouched.
	UpdatePageProperties(pageID string, properties map[string]interface{}) error
	// ArchivePage moves a page to the workspace trash. Notion's API has
	// no true permanent delete for pages - this is the only supported
	// mechanism, and it's recoverable from Notion's UI.
	ArchivePage(pageID string) error
}

// NotionClient is the default NotionClientInterface implementation. It
// talks to the real Notion REST API directly over HTTP, rather than via a
// third-party SDK, so that the exact request shapes (verified against
// Notion's own API reference) are fully under our control.
type NotionClient struct {
	AuthToken  string
	HTTPClient *http.Client
}

// NewNotionClient returns a NotionClient configured to authenticate with
// the given integration token.
func NewNotionClient(authToken string) *NotionClient {
	return &NotionClient{
		AuthToken:  authToken,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *NotionClient) request(method string, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Notion request body: %w", err)
		}
		reqBody = bytes.NewReader(payload)
	}

	req, err := http.NewRequest(method, NOTION_API_BASE+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to build Notion request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	req.Header.Set("Notion-Version", NOTION_API_VERSION)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send Notion request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Notion response body: %w", err)
	}

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("notion API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// CreateDatabaseRow implements NotionClientInterface. Page creation accepts
// an initial `children` array subject to the same limits as append-block-
// children (100 elements at the top level, two levels of nesting). If more
// than 100 top-level blocks are given, this creates the page with the first
// 100 and appends the rest afterward via the newly created page's own ID.
func (c *NotionClient) CreateDatabaseRow(
	databaseID string,
	properties map[string]interface{},
	blocks []map[string]interface{},
) (string, error) {
	initialBlocks := blocks
	var overflowBlocks []map[string]interface{}
	if len(blocks) > notionMaxBlocksPerRequest {
		initialBlocks = blocks[:notionMaxBlocksPerRequest]
		overflowBlocks = blocks[notionMaxBlocksPerRequest:]
	}

	body := map[string]interface{}{
		"parent": map[string]interface{}{
			"database_id": databaseID,
		},
		"properties": properties,
	}
	if len(initialBlocks) > 0 {
		body["children"] = initialBlocks
	}

	respBody, err := c.request(http.MethodPost, "/pages", body)
	if err != nil {
		return "", err
	}

	var parsed struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("failed to parse Notion create-page response: %w", err)
	}

	if len(overflowBlocks) > 0 {
		if err := c.appendBlockChildrenBatched(parsed.ID, overflowBlocks); err != nil {
			return parsed.ID, fmt.Errorf("failed to append remaining content to new Notion row: %w", err)
		}
	}

	return parsed.ID, nil
}

// notionBlockSummary is the subset of a Notion block object this client
// actually needs when listing a block's children: enough to identify it
// (ID) and, for GetToggleBlockChildrenIDs, to filter by shape (Type).
type notionBlockSummary struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type notionBlockListResponse struct {
	Results    []notionBlockSummary `json:"results"`
	HasMore    bool                 `json:"has_more"`
	NextCursor string               `json:"next_cursor"`
}

// getBlockChildren returns all of a block's (or page's) direct children,
// following pagination.
func (c *NotionClient) getBlockChildren(blockID string) ([]notionBlockSummary, error) {
	var all []notionBlockSummary
	cursor := ""
	for {
		path := fmt.Sprintf("/blocks/%s/children?page_size=100", blockID)
		if cursor != "" {
			path += "&start_cursor=" + cursor
		}
		respBody, err := c.request(http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		var parsed notionBlockListResponse
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			return nil, fmt.Errorf("failed to parse Notion block children response: %w", err)
		}
		all = append(all, parsed.Results...)
		if !parsed.HasMore {
			break
		}
		cursor = parsed.NextCursor
	}
	return all, nil
}

// getBlockChildrenIDs returns the IDs of ALL of a block's direct children,
// regardless of type. Used internally by ReplacePageContent to find
// everything that needs deleting before a page refresh.
func (c *NotionClient) getBlockChildrenIDs(blockID string) ([]string, error) {
	children, err := c.getBlockChildren(blockID)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(children))
	for i, child := range children {
		ids[i] = child.ID
	}
	return ids, nil
}

// GetToggleBlockChildrenIDs implements NotionClientInterface.
func (c *NotionClient) GetToggleBlockChildrenIDs(blockID string) ([]string, error) {
	children, err := c.getBlockChildren(blockID)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(children))
	for _, child := range children {
		if child.Type == "toggle" {
			ids = append(ids, child.ID)
		}
	}
	return ids, nil
}

type notionDatabaseQueryRow struct {
	ID         string `json:"id"`
	Properties map[string]struct {
		// Only the title property will ever have a non-empty Title here;
		// every other property type's JSON simply lacks a "title" key, so
		// this comes back as an empty slice for them. That's what lets
		// QueryDatabaseTitles find the title property without needing to
		// assume it's named "Name" (or anything else) - see its own
		// comment for why that assumption would be fragile.
		Title []struct {
			PlainText string `json:"plain_text"`
		} `json:"title"`
	} `json:"properties"`
}

type notionDatabaseQueryResponse struct {
	Results    []notionDatabaseQueryRow `json:"results"`
	HasMore    bool                     `json:"has_more"`
	NextCursor string                   `json:"next_cursor"`
}

// QueryDatabaseTitles implements NotionClientInterface.
func (c *NotionClient) QueryDatabaseTitles(databaseID string) (map[string]string, error) {
	titles := make(map[string]string)
	cursor := ""
	for {
		body := map[string]interface{}{"page_size": 100}
		if cursor != "" {
			body["start_cursor"] = cursor
		}
		respBody, err := c.request(http.MethodPost, "/databases/"+databaseID+"/query", body)
		if err != nil {
			return nil, err
		}
		var parsed notionDatabaseQueryResponse
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			return nil, fmt.Errorf("failed to parse Notion database query response: %w", err)
		}
		for _, row := range parsed.Results {
			for _, value := range row.Properties {
				if len(value.Title) == 0 {
					continue
				}
				var name strings.Builder
				for _, span := range value.Title {
					name.WriteString(span.PlainText)
				}
				titles[name.String()] = row.ID
				break // exactly one title property exists per database
			}
		}
		if !parsed.HasMore {
			break
		}
		cursor = parsed.NextCursor
	}
	return titles, nil
}

// UpdatePageProperties implements NotionClientInterface.
func (c *NotionClient) UpdatePageProperties(pageID string, properties map[string]interface{}) error {
	body := map[string]interface{}{"properties": properties}
	_, err := c.request(http.MethodPatch, "/pages/"+pageID, body)
	return err
}

// ArchivePage implements NotionClientInterface.
//
// This uses "archived" rather than the newer "in_trash" field, to match
// the pinned NOTION_API_VERSION ("2022-06-28") this client speaks - verify
// this still behaves as expected if that version is ever bumped. Notion's
// docs (checked while building this) note that as of a March 2026 change,
// newer API versions only accept "in_trash", with "archived" kept only as
// a deprecated alias for older, already-pinned versions - not a hard
// guarantee that alias lasts forever.
func (c *NotionClient) ArchivePage(pageID string) error {
	body := map[string]interface{}{"archived": true}
	_, err := c.request(http.MethodPatch, "/pages/"+pageID, body)
	return err
}

func (c *NotionClient) deleteBlock(blockID string) error {
	_, err := c.request(http.MethodDelete, "/blocks/"+blockID, nil)
	return err
}

// appendBlockChildrenBatched appends the given blocks to a page/block,
// batching requests to stay under Notion's 100-blocks-per-request limit.
// Shared by AppendBlockChildren and CreateDatabaseRow's overflow handling.
func (c *NotionClient) appendBlockChildrenBatched(blockID string, blocks []map[string]interface{}) error {
	for start := 0; start < len(blocks); start += notionMaxBlocksPerRequest {
		end := start + notionMaxBlocksPerRequest
		if end > len(blocks) {
			end = len(blocks)
		}
		body := map[string]interface{}{
			"children": blocks[start:end],
		}
		if _, err := c.request(http.MethodPatch, "/blocks/"+blockID+"/children", body); err != nil {
			return err
		}
	}
	return nil
}

// AppendBlockChildren implements NotionClientInterface.
func (c *NotionClient) AppendBlockChildren(blockID string, blocks []map[string]interface{}) error {
	return c.appendBlockChildrenBatched(blockID, blocks)
}

// ReplacePageContent implements NotionClientInterface. Notion has no
// single "clear a page" call, so this fetches the page's existing children,
// deletes them one at a time, and then appends the new content.
func (c *NotionClient) ReplacePageContent(pageID string, blocks []map[string]interface{}) error {
	existingIDs, err := c.getBlockChildrenIDs(pageID)
	if err != nil {
		return fmt.Errorf("failed to fetch existing Notion page content: %w", err)
	}
	for _, id := range existingIDs {
		if err := c.deleteBlock(id); err != nil {
			return fmt.Errorf("failed to clear existing Notion block %s: %w", id, err)
		}
	}
	return c.appendBlockChildrenBatched(pageID, blocks)
}

// --- Page property builders (see buildHistoryRowProperties) ---
// Shapes verified directly against
// https://developers.notion.com/reference/page-property-values

func notionTitleProperty(content string) map[string]interface{} {
	return map[string]interface{}{
		"title": []map[string]interface{}{
			{"text": map[string]interface{}{"content": content}},
		},
	}
}

func notionSelectProperty(name string) map[string]interface{} {
	return map[string]interface{}{
		"select": map[string]interface{}{"name": name},
	}
}

// notionMultiSelectProperty builds a multi-select property from a list of
// option names. As with notionSelectProperty, option colors are read-only
// and auto-assigned by Notion, and commas aren't valid within an option
// name (not handled defensively here - see the implementation guidelines
// for this same caveat noted elsewhere).
func notionMultiSelectProperty(names []string) map[string]interface{} {
	options := make([]map[string]interface{}, 0, len(names))
	for _, name := range names {
		options = append(options, map[string]interface{}{"name": name})
	}
	return map[string]interface{}{"multi_select": options}
}

// notionCheckboxProperty builds a checkbox property from a plain bool.
func notionCheckboxProperty(value bool) map[string]interface{} {
	return map[string]interface{}{"checkbox": value}
}

// notionVisibilityLabels maps GitHub's raw GraphQL visibility values to a
// nicer display label. Deliberately not using GitHub's older isPrivate
// boolean anywhere upstream of this (see querying.Project.Visibility's own
// comment) - that field can't distinguish Private from Internal
// (GitHub Enterprise-only) repos, since it returns true for both.
var notionVisibilityLabels = map[string]string{
	"PUBLIC":   "Public",
	"PRIVATE":  "Private",
	"INTERNAL": "Internal",
}

// notionVisibilityLabel returns the display label for a repo's raw GitHub
// visibility value, falling back to the raw value itself (or "Unknown" if
// empty) for anything unrecognized, rather than silently showing a blank
// tag - GitHub could add a new visibility value in the future, and an
// unrecognized-but-visible value is more useful than a blank one.
func notionVisibilityLabel(visibility string) string {
	if visibility == "" {
		return "Unknown"
	}
	if label, ok := notionVisibilityLabels[visibility]; ok {
		return label
	}
	return visibility
}

func notionNumberProperty(value int) map[string]interface{} {
	return map[string]interface{}{"number": value}
}

// notionDateProperty formats a Notion date property. Whether Notion
// displays a time alongside the date is controlled entirely by whether the
// ISO 8601 string itself includes a time component - verified directly
// against Notion's docs, not assumed. time.RFC3339 (e.g.
// "2026-09-19T14:35:00Z") includes one, so the row shows both.
func notionDateProperty(t time.Time) map[string]interface{} {
	return map[string]interface{}{
		"date": map[string]interface{}{"start": t.Format(time.RFC3339)},
	}
}

// buildHistoryRowProperties builds the page properties for one row of the
// shared history database, representing one team's report.
//
// This expects a database with the schema documented in the implementation
// guidelines: a "Name" title property, plus Team (select), Date (date),
// Total Findings / Affected Repos / Critical / High / Moderate / Low
// (number), and Highest Severity (select).
func buildHistoryRowProperties(
	title string,
	team string,
	report FindingSummary,
	reportTime time.Time,
) map[string]interface{} {
	return map[string]interface{}{
		"Name":             notionTitleProperty(title),
		"Team":             notionSelectProperty(team),
		"Date":             notionDateProperty(reportTime),
		"Total Findings":   notionNumberProperty(report.TotalCount),
		"Affected Repos":   notionNumberProperty(report.AffectedRepos),
		"Critical":         notionNumberProperty(report.VulnsBySeverity[configs.FindingSeverityCritical]),
		"High":             notionNumberProperty(report.VulnsBySeverity[configs.FindingSeverityHigh]),
		"Moderate":         notionNumberProperty(report.VulnsBySeverity[configs.FindingSeverityModerate]),
		"Low":              notionNumberProperty(report.VulnsBySeverity[configs.FindingSeverityLow]),
		"Highest Severity": notionSelectProperty(SeverityNames[report.GetHighestCriticality()]),
	}
}

// buildOwnershipRowProperties builds the page properties for one row of
// the repo ownership registry database: the repo's name (a title
// property, linked to its plain repo URL when available - see
// notionOwnershipRepoURL for why that's not just Project.Link directly -
// falling back to plain text if there's nothing to link to, since sending
// Notion a link object with an empty URL risks a validation error), its
// owning team(s) as a multi-select (or a literal "Unowned" tag if it has
// none - team names are sorted for a stable, deterministic tag order
// rather than whatever order the underlying set iterates in), its
// visibility (see notionVisibilityLabel), and whether it's a fork.
//
// Expects a database with a title property (any name - QueryDatabaseTitles
// doesn't assume "Name", but writes here do, per the setup convention
// used for every other database in this reporter), an "Owning Teams"
// multi-select property, a "Visibility" select property, and an "Is Fork"
// checkbox property.
// notionGithubSecuritySuffix is the suffix every known DataSource appends
// when setting Project.Link (see querying/github.go and querying/codeql.go
// - both build it as `<repo HTML URL>/security`). That page requires
// GitHub Security tab access (Admin/Maintain) to view, which is exactly
// right for the vulnerability-listing content elsewhere in this reporter
// (aimed at people already fixing the vulnerabilities, who need that
// access anyway) but wrong for the ownership registry below, which is
// meant to be readable by anyone trying to figure out who owns a repo -
// most of whom won't have that access. Trimmed off there to link to the
// plain repo page instead.
const notionGithubSecuritySuffix = "/security"

// notionOwnershipRepoURL returns the plain repo URL for the ownership
// registry, stripping the /security suffix Project.Link always carries -
// see notionGithubSecuritySuffix. Returns "" (same as an unset Link
// entirely) if nothing is left after trimming, so the existing
// empty-link-means-no-link handling in buildOwnershipRowProperties still
// applies without special-casing.
func notionOwnershipRepoURL(project *querying.Project) string {
	return strings.TrimSuffix(project.Link, notionGithubSecuritySuffix)
}

func buildOwnershipRowProperties(project *querying.Project) map[string]interface{} {
	teamNames := make([]string, 0, project.Owners.Cardinality())
	ownerIter := project.Owners.Iterator()
	for owner := range ownerIter.C {
		teamNames = append(teamNames, owner.Name)
	}
	sort.Strings(teamNames)
	if len(teamNames) == 0 {
		teamNames = []string{"Unowned"}
	}

	nameSpan := notionPlainTextSpan(project.Name)
	if repoURL := notionOwnershipRepoURL(project); repoURL != "" {
		nameSpan = notionLinkedTextSpan(project.Name, repoURL)
	}

	return map[string]interface{}{
		"Name":         map[string]interface{}{"title": []map[string]interface{}{nameSpan}},
		"Owning Teams": notionMultiSelectProperty(teamNames),
		"Visibility":   notionSelectProperty(notionVisibilityLabel(project.Visibility)),
		"Is Fork":      notionCheckboxProperty(project.IsFork),
	}
}

// --- Block builders for the persistent "latest" pages ---

func notionHeadingBlock(text string) map[string]interface{} {
	return map[string]interface{}{
		"object": "block",
		"type":   "heading_2",
		"heading_2": map[string]interface{}{
			"rich_text": []map[string]interface{}{
				{"type": "text", "text": map[string]interface{}{"content": text}},
			},
		},
	}
}

func notionParagraphBlock(text string) map[string]interface{} {
	return map[string]interface{}{
		"object": "block",
		"type":   "paragraph",
		"paragraph": map[string]interface{}{
			"rich_text": []map[string]interface{}{
				{"type": "text", "text": map[string]interface{}{"content": text}},
			},
		},
	}
}

func notionCalloutBlock(text string, color string) map[string]interface{} {
	return map[string]interface{}{
		"object": "block",
		"type":   "callout",
		"callout": map[string]interface{}{
			"rich_text": []map[string]interface{}{
				{"type": "text", "text": map[string]interface{}{"content": text}},
			},
			"color": color,
		},
	}
}

func notionBulletedListItemBlock(richText []map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"object": "block",
		"type":   "bulleted_list_item",
		"bulleted_list_item": map[string]interface{}{
			"rich_text": richText,
		},
	}
}

func notionDividerBlock() map[string]interface{} {
	return map[string]interface{}{
		"object":  "block",
		"type":    "divider",
		"divider": map[string]interface{}{},
	}
}

// notionToggleBlock builds a collapsible toggle block with the given rich
// text as its title and the given children embedded directly (Notion
// supports one level of nested `children` per block in a single request -
// see notionFindingBlocks for why this can't safely go any deeper).
// Takes a rich_text array rather than a plain string so callers can mix
// plain and linked spans in one title (see notionRepoToggleBlock).
func notionToggleBlock(richText []map[string]interface{}, children []map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"object": "block",
		"type":   "toggle",
		"toggle": map[string]interface{}{
			"rich_text": richText,
			"children":  children,
		},
	}
}

// notionPlainTextSpan builds one plain (unlinked) rich-text span.
func notionPlainTextSpan(content string) map[string]interface{} {
	return map[string]interface{}{
		"type": "text",
		"text": map[string]interface{}{"content": content},
	}
}

// notionLinkedTextSpan builds one rich-text span that renders as a
// clickable link, per Notion's rich text object shape (a "link" object
// nested inside "text", alongside "content").
func notionLinkedTextSpan(content string, url string) map[string]interface{} {
	return map[string]interface{}{
		"type": "text",
		"text": map[string]interface{}{
			"content": content,
			"link":    map[string]interface{}{"url": url},
		},
	}
}

// notionCVEBaseURL is NVD's CVE detail page - the standard, current URL
// format for linking directly to a given CVE's public record (verified,
// e.g. https://nvd.nist.gov/vuln/detail/CVE-2024-9999).
const notionCVEBaseURL = "https://nvd.nist.gov/vuln/detail/"

func notionCVEURL(cve string) string {
	return notionCVEBaseURL + cve
}

// notionIdentifierSpans builds rich-text spans for a Finding's CVE and/or
// GHSA identifiers (whichever are present), in a stable order (map
// iteration order in Go is randomized, so this checks each known
// identifier type explicitly rather than ranging over the map). The CVE
// identifier, if present, links directly to its NVD record. GHSA is
// rendered as plain text for now - only a CVE link was requested; linking
// GHSA too (e.g. https://github.com/advisories/<id>) would be a small,
// symmetric follow-up if wanted.
func notionIdentifierSpans(identifiers querying.FindingIdentifierMap) []map[string]interface{} {
	cve, hasCVE := identifiers[querying.FindingIdentifierCVE]
	hasCVE = hasCVE && cve != ""
	ghsa, hasGHSA := identifiers[querying.FindingIdentifierGHSA]
	hasGHSA = hasGHSA && ghsa != ""

	spans := make([]map[string]interface{}, 0, 3)
	if hasCVE {
		spans = append(spans, notionLinkedTextSpan(cve, notionCVEURL(cve)))
	}
	if hasCVE && hasGHSA {
		spans = append(spans, notionPlainTextSpan(" / "))
	}
	if hasGHSA {
		spans = append(spans, notionPlainTextSpan(ghsa))
	}
	if !hasCVE && !hasGHSA {
		spans = append(spans, notionPlainTextSpan("(no identifier)"))
	}
	return spans
}

func truncateFindingDescription(description string) string {
	if len(description) <= notionMaxDescriptionLength {
		return description
	}
	return description[:notionMaxDescriptionLength] + "..."
}

// notionFindingBulletBlock renders one Finding as a bulleted list item:
// severity, identifier(s) (CVE linked to NVD, per notionIdentifierSpans),
// affected package, and a (possibly truncated) description.
func notionFindingBulletBlock(finding *querying.Finding) map[string]interface{} {
	richText := make([]map[string]interface{}, 0, 5)
	richText = append(richText, notionPlainTextSpan(fmt.Sprintf("[%s] ", SeverityNames[finding.Severity])))
	richText = append(richText, notionIdentifierSpans(finding.Identifiers)...)
	richText = append(richText, notionPlainTextSpan(fmt.Sprintf(
		" — %s\n%s",
		finding.PackageName,
		truncateFindingDescription(finding.Description),
	)))
	return notionBulletedListItemBlock(richText)
}

// severityFindingGroup buckets one severity tier's findings for a repo.
type severityFindingGroup struct {
	Severity configs.FindingSeverityType
	Findings []*querying.Finding
}

// groupFindingsBySeverity buckets a repo's findings by severity, ordered
// Critical -> High -> Moderate -> Low -> Info -> Undefined via
// GetSeverityReportOrder(), including only tiers that actually have at
// least one finding. This is what lets each severity tier become its own
// independently-collapsible toggle (see notionRepoToggleBlock), rather
// than one flat list - it both orders and groups findings in one pass, so
// there's no separate sort step needed elsewhere.
func groupFindingsBySeverity(findings []*querying.Finding) []severityFindingGroup {
	buckets := make(map[configs.FindingSeverityType][]*querying.Finding)
	for _, finding := range findings {
		buckets[finding.Severity] = append(buckets[finding.Severity], finding)
	}

	groups := make([]severityFindingGroup, 0, len(buckets))
	for _, severity := range GetSeverityReportOrder() {
		findingsForSeverity, exists := buckets[severity]
		if !exists || len(findingsForSeverity) == 0 {
			continue
		}
		groups = append(groups, severityFindingGroup{Severity: severity, Findings: findingsForSeverity})
	}
	return groups
}

// notionFindingBlocks renders one severity group's findings as bullet
// blocks. Notion caps any single `children` array at 100 elements, so if a
// single severity tier somehow has more than that many findings for one
// repo, this truncates and adds a note rather than risk the whole append
// request failing outright.
func notionFindingBlocks(findings []*querying.Finding) []map[string]interface{} {
	limit := len(findings)
	truncated := false
	if limit > notionMaxNestedChildren-1 { // leave room for the truncation notice itself
		limit = notionMaxNestedChildren - 1
		truncated = true
	}

	blocks := make([]map[string]interface{}, 0, limit+1)
	for _, finding := range findings[:limit] {
		blocks = append(blocks, notionFindingBulletBlock(finding))
	}
	if truncated {
		blocks = append(blocks, notionParagraphBlock(fmt.Sprintf(
			"... and %d more findings not shown here (see the repository directly for the full list).",
			len(findings)-limit,
		)))
	}
	return blocks
}

// notionRepoToggleBlock builds one repo's toggle: its title is the repo
// name (linked to Project.Link when available) followed by the
// severity-count summary. Its children are, in turn, one toggle per
// severity tier actually present - so someone can open just "Critical" on
// a given repo without wading through every other tier.
//
// These severity toggles are created WITHOUT their own finding-bullet
// children yet, even though that's the whole point of them: Notion allows
// at most two levels of nesting in a single request, and repo-toggle ->
// severity-toggle is already that second level. The third level (the
// actual finding bullets) has to be attached in a follow-up call once
// Notion hands back these blocks' real IDs - see attachSeverityFindings.
func notionRepoToggleBlock(repo *ProjectFindingSummary) map[string]interface{} {
	vulnCounts := make([]string, 0)
	for _, severity := range GetSeverityReportOrder() {
		count, exists := repo.VulnsBySeverity[severity]
		if exists {
			vulnCounts = append(vulnCounts, fmt.Sprintf("%d %s", count, SeverityNames[severity]))
		}
	}

	// The repo name itself is the clickable link, rather than pasting the
	// raw URL alongside it as visible text. Falls back to a plain span if
	// a project somehow has no link, rather than sending Notion a link
	// object with an empty URL.
	nameSpan := notionPlainTextSpan(repo.Project.Name)
	if repo.Project.Link != "" {
		nameSpan = notionLinkedTextSpan(repo.Project.Name, repo.Project.Link)
	}
	titleRichText := []map[string]interface{}{
		nameSpan,
		notionPlainTextSpan(fmt.Sprintf(" - %s", strings.Join(vulnCounts, " | "))),
	}

	groups := groupFindingsBySeverity(repo.Project.Findings)
	severityToggles := make([]map[string]interface{}, 0, len(groups))
	for _, group := range groups {
		severityTitle := fmt.Sprintf("%s (%d)", SeverityNames[group.Severity], len(group.Findings))
		severityToggles = append(severityToggles, notionToggleBlock(
			[]map[string]interface{}{notionPlainTextSpan(severityTitle)},
			[]map[string]interface{}{}, // filled in afterward by attachSeverityFindings
		))
	}

	return notionToggleBlock(titleRichText, severityToggles)
}

// buildRepoToggleBlocks renders every real repo (skipping the synthetic
// SUMMARY_KEY entry) in a team's collection as a toggle block via
// notionRepoToggleBlock. Shared between the persistent team page and each
// run's history-database row, so both show the same repo/finding detail -
// though callers may pre-filter which repos they pass in (see
// reposWithFindings) to show different subsets on each.
//
// Also returns the same filtered, ordered slice of repos the blocks were
// built from. attachSeverityFindings needs this exact list, in this exact
// order, to reconcile against the toggle IDs Notion assigns after
// creation - returning both from one function guarantees they can never
// drift out of sync with each other.
func buildRepoToggleBlocks(repos TeamProjectCollection) ([]map[string]interface{}, []*ProjectFindingSummary) {
	blocks := make([]map[string]interface{}, 0, len(repos))
	filteredRepos := make([]*ProjectFindingSummary, 0, len(repos))
	for _, repo := range repos {
		if repo.Project.Name == SUMMARY_KEY {
			continue
		}
		blocks = append(blocks, notionRepoToggleBlock(repo))
		filteredRepos = append(filteredRepos, repo)
	}
	return blocks, filteredRepos
}

// reposWithFindings filters a team's repos down to just the ones with at
// least one finding, preserving order. Used for the history-database row's
// body content specifically: unlike the persistent team page (which lists
// every repo the team owns, clean or not, as a full roster), each run's
// archived row is meant to be a record of what was actually flagged that
// run - a repo with nothing to report there is noise, not information.
// Checks Project.Findings directly (the source of truth) rather than a
// pre-aggregated count field, consistent with how the rest of this
// reporter avoids trusting aggregate fields that have turned out to be
// unreliable before (see getTeamAffectedRepoCount).
func reposWithFindings(repos TeamProjectCollection) TeamProjectCollection {
	filtered := make(TeamProjectCollection, 0, len(repos))
	for _, repo := range repos {
		if len(repo.Project.Findings) > 0 {
			filtered = append(filtered, repo)
		}
	}
	return filtered
}

// attachSeverityFindings fills in the third level of nesting that
// notionRepoToggleBlock had to leave empty: for each repo toggle just
// created under containerID (a page or database row), it looks up that
// toggle's real ID, finds its severity sub-toggles, and appends that
// severity's finding bullets into each one.
//
// repos must be exactly the filtered, ordered slice buildRepoToggleBlocks
// returned alongside the blocks that were just written to containerID -
// this walks Notion's response positionally (repo toggles and severity
// toggles come back in the same order they were sent), not by matching on
// content, so an ordering mismatch here would attach the wrong findings to
// the wrong repo.
//
// This is inherently best-effort: any mismatch or failure is logged and
// that repo (or the whole call) is skipped, rather than treated as fatal -
// consistent with how every other Notion write in this reporter behaves
// when one piece fails.
func (n *NotionReporter) attachSeverityFindings(containerID string, repos []*ProjectFindingSummary) {
	log := logger.Get()

	repoToggleIDs, err := n.Client.GetToggleBlockChildrenIDs(containerID)
	if err != nil {
		log.Error().Err(err).Msg("Failed to look up newly created Notion repo toggles; findings were not attached.")
		return
	}
	if len(repoToggleIDs) != len(repos) {
		log.Error().
			Int("expected", len(repos)).
			Int("found", len(repoToggleIDs)).
			Msg("Notion repo toggle count did not match the expected repos; findings were not attached.")
		return
	}

	for i, repo := range repos {
		groups := groupFindingsBySeverity(repo.Project.Findings)

		severityToggleIDs, err := n.Client.GetToggleBlockChildrenIDs(repoToggleIDs[i])
		if err != nil {
			log.Error().Err(err).Str("repo", repo.Project.Name).
				Msg("Failed to look up Notion severity toggles for repo; findings were not attached for this repo.")
			continue
		}
		if len(severityToggleIDs) != len(groups) {
			log.Error().Str("repo", repo.Project.Name).
				Int("expected", len(groups)).
				Int("found", len(severityToggleIDs)).
				Msg("Notion severity toggle count did not match for repo; findings were not attached for this repo.")
			continue
		}

		for j, group := range groups {
			err := n.Client.AppendBlockChildren(severityToggleIDs[j], notionFindingBlocks(group.Findings))
			if err != nil {
				log.Error().Err(err).
					Str("repo", repo.Project.Name).
					Str("severity", SeverityNames[group.Severity]).
					Msg("Failed to attach findings to Notion severity toggle.")
			}
		}
	}
}

// buildSummaryPageBlocks lays out the content for the persistent org-wide
// summary page, mirroring the sections ConsoleReporter.SendSummaryReport
// and SlackReporter.BuildSummaryReport already render (total counts,
// per-team breakdown, per-severity breakdown, per-ecosystem breakdown).
func buildSummaryPageBlocks(
	numRepos int,
	report FindingSummary,
	reportTime time.Time,
	teamSummaries TeamSummaries,
) []map[string]interface{} {
	blocks := []map[string]interface{}{
		notionParagraphBlock(reportTime.Format(notionPageTimestampLayout)),
		notionParagraphBlock(fmt.Sprintf("Total Vulnerabilities: %d", report.TotalCount)),
		notionParagraphBlock(fmt.Sprintf("Affected Repositories: %d", report.AffectedRepos)),
		notionParagraphBlock(fmt.Sprintf("Total Repositories: %d", numRepos)),
	}

	blocks = append(blocks, notionDividerBlock(), notionHeadingBlock("Team Breakdown"))
	teamsBreakdown := calculateTeamBreakdown(teamSummaries)
	sort.Slice(teamsBreakdown, func(i, j int) bool {
		return teamsBreakdown[i].TotalVulnerabilities > teamsBreakdown[j].TotalVulnerabilities
	})
	for _, team := range teamsBreakdown {
		blocks = append(blocks, notionParagraphBlock(
			fmt.Sprintf("%s: %d %s", team.Name, team.TotalVulnerabilities, GetVulnerabilityWord(team.TotalVulnerabilities)),
		))
	}

	blocks = append(blocks, notionDividerBlock(), notionHeadingBlock("Severity Breakdown"))
	for _, severity := range GetSeverityReportOrder() {
		count, exists := report.VulnsBySeverity[severity]
		if exists {
			blocks = append(blocks, notionCalloutBlock(
				fmt.Sprintf("%s: %d", SeverityNames[severity], count),
				getNotionColorForSeverity(severity),
			))
		}
	}

	blocks = append(blocks, notionDividerBlock(), notionHeadingBlock("Ecosystem Breakdown"))
	ecosystems := maps.Keys(report.VulnsByEcosystem)
	sort.Slice(ecosystems, func(i, j int) bool { return ecosystems[i] < ecosystems[j] })
	for _, ecosystem := range ecosystems {
		blocks = append(blocks, notionParagraphBlock(
			fmt.Sprintf("%s: %d", ecosystem, report.VulnsByEcosystem[ecosystem]),
		))
	}

	return blocks
}

// buildTeamPageBlocks lays out the content for one team's persistent page,
// mirroring the data SlackReporter.BuildTeamReport uses. Unlike the Slack
// version, this includes a full severity breakdown for the team (via
// GetTeamSeverityBreakdown) rather than only a total count - see the
// implementation guidelines for why the Slack version's summary section
// doesn't do this today.
//
// Unlike the history-database row (see reposWithFindings), this lists
// EVERY repo the team owns, whether or not it currently has findings - the
// persistent page is meant as an always-current roster, not just a record
// of what was flagged.
//
// Also returns the filtered, ordered repo list buildRepoToggleBlocks used,
// so the caller can hand it straight to attachSeverityFindings without a
// second, redundant call.
func buildTeamPageBlocks(
	teamInfo configs.TeamConfig,
	repos TeamProjectCollection,
	reportTime time.Time,
) ([]map[string]interface{}, []*ProjectFindingSummary) {
	sort.Sort(repos)
	summary := repos.GetTeamSummaryReport()
	severityBreakdown := repos.GetTeamSeverityBreakdown()

	totalCount := 0
	if summary != nil {
		totalCount = summary.TotalCount
	}

	blocks := []map[string]interface{}{
		notionHeadingBlock(fmt.Sprintf("%s Vulnbot Report", teamInfo.Name)),
		notionParagraphBlock(reportTime.Format(notionPageTimestampLayout)),
		notionParagraphBlock(fmt.Sprintf("%d Total %s", totalCount, GetVulnerabilityWord(totalCount))),
	}

	blocks = append(blocks, notionDividerBlock(), notionHeadingBlock("Severity Breakdown"))
	for _, severity := range GetSeverityReportOrder() {
		count, exists := severityBreakdown[severity]
		if exists && count > 0 {
			blocks = append(blocks, notionCalloutBlock(
				fmt.Sprintf("%s: %d", SeverityNames[severity], count),
				getNotionColorForSeverity(severity),
			))
		}
	}

	blocks = append(blocks, notionDividerBlock(), notionHeadingBlock("Repositories"))
	repoBlocks, pageRepos := buildRepoToggleBlocks(repos)
	blocks = append(blocks, repoBlocks...)

	return blocks, pageRepos
}

// NotionReporter reports findings out to Notion: one row per report in a
// shared history database, plus a persistent "latest" page per report that
// is fully overwritten on each run. See the implementation guidelines doc
// for the full design rationale.
type NotionReporter struct {
	Config *configs.Config
	Client NotionClientInterface
	// TeamPagesOnly, when true, makes this reporter skip everything
	// except each team's persistent page refresh: no org-wide summary
	// page write, and no row written to the shared history database.
	// Meant for running Notion reporting on a much more frequent schedule
	// (e.g. every couple of hours) than the heavier summary/history/
	// ownership work needs - see NewNotionTeamPagesReporter and the
	// "notion-per-team" dispatch in internal/scan.go's buildReporters.
	TeamPagesOnly bool
}

// NewNotionReporter returns a new NotionReporter instance configured to do
// everything this reporter supports: the org-wide summary page, each
// team's row in the shared history database, and each team's persistent
// page. Both the auth token and the shared history database ID are
// required; the summary page and per-team pages are optional (skipped if
// not configured). For a lighter-weight reporter restricted to just team
// pages - meant to run on its own, more frequent schedule - see
// NewNotionTeamPagesReporter instead.
func NewNotionReporter(cfg *configs.Config) (NotionReporter, error) {
	if cfg.Notion_auth_token == "" {
		return NotionReporter{}, errors.New("no Notion token was provided")
	}
	if cfg.Notion_database_id == "" {
		return NotionReporter{}, errors.New("no Notion database ID was configured")
	}
	client := NewNotionClient(cfg.Notion_auth_token)
	return NotionReporter{Config: cfg, Client: client}, nil
}

// NewNotionTeamPagesReporter returns a NotionReporter restricted to only
// ever refreshing each team's persistent page (TeamPagesOnly - see its own
// comment). Unlike NewNotionReporter, this does NOT require
// Notion_database_id, since that database is never touched in this mode -
// only the auth token is required. Notion_summary_page_id,
// Notion_database_id, and Notion_ownership_database_id can all be left set
// in the shared config; they're simply never read by an instance created
// this way, the same as they already are for teams with no Notion_page_id
// configured.
func NewNotionTeamPagesReporter(cfg *configs.Config) (NotionReporter, error) {
	if cfg.Notion_auth_token == "" {
		return NotionReporter{}, errors.New("no Notion token was provided")
	}
	client := NewNotionClient(cfg.Notion_auth_token)
	return NotionReporter{Config: cfg, Client: client, TeamPagesOnly: true}, nil
}

// SendSummaryReport writes the org-wide summary to Notion by overwriting
// the persistent summary page (if configured). Unlike SendTeamReports, this
// does NOT write a row to the shared history database - that database is
// for per-team rows only, so a "Team" filter/view there reflects only real
// teams, with no org-wide rollup mixed in.
//
// header is accepted (and unused below) only to satisfy the shared
// Reporter interface - Slack and Console both use it as their message
// title, but Notion deliberately doesn't: it's Slack-formatted text (emoji
// shortcodes like ":robot_face:" that Slack renders as 🤖 but Notion just
// shows as literal colon-wrapped text), and the persistent page's own
// Notion page title already gives it a heading, making a second one inside
// the body redundant on top of looking broken.
//
// This does not spawn additional goroutines the way SlackReporter does;
// per the implementation guidelines, Notion writes are kept sequential to
// stay comfortably under Notion's rate limit. The caller (internal/scan.go)
// already runs this method in its own goroutine per reporter.
func (n *NotionReporter) SendSummaryReport(
	header string,
	numRepos int,
	report FindingSummary,
	reportTime time.Time,
	teamSummaries TeamSummaries,
	wg *sync.WaitGroup,
) error {
	defer wg.Done()
	log := logger.Get()

	if n.TeamPagesOnly {
		log.Debug().Msg("Skipping Notion summary report; this reporter instance is restricted to team pages only.")
		return nil
	}

	if n.Client == nil {
		log.Warn().Msg("No Notion client available. Summary report not sent.")
		return nil
	}

	if n.Config.Notion_summary_page_id != "" {
		blocks := buildSummaryPageBlocks(numRepos, report, reportTime, teamSummaries)
		if err := n.Client.ReplacePageContent(n.Config.Notion_summary_page_id, blocks); err != nil {
			log.Error().Err(err).Msg("Failed to refresh Notion summary page.")
		}
	} else {
		log.Debug().Msg("Skipping Notion summary page refresh since Notion_summary_page_id is not configured.")
	}

	return nil
}

// SendTeamReports writes each team's report to Notion: a new row per team
// in the shared history database, and (for teams with a configured
// Notion_page_id) an overwrite of that team's persistent page. As with
// SendSummaryReport, these writes are sequential and independent of one
// another's success or failure.
func (n *NotionReporter) SendTeamReports(
	teamReports map[configs.TeamConfig]TeamProjectCollection,
	reportTime time.Time,
	wg *sync.WaitGroup,
) error {
	defer wg.Done()
	log := logger.Get()

	if n.Client == nil {
		log.Warn().Msg("No Notion client available. Team reports not sent.")
		return nil
	}

	for team, repos := range teamReports {
		sort.Sort(repos)
		summary := repos.GetTeamSummaryReport()
		if summary == nil {
			log.Debug().Str("team", team.Name).Msg("Skipping Notion report for team with no summary entry.")
			continue
		}

		if !n.TeamPagesOnly {
			// summary.AffectedRepos can't be trusted here: GroupTeamFindings
			// (reporting/summary.go) only aggregates TotalCount onto the
			// synthetic per-team summary entry, leaving its AffectedRepos at
			// its zero value always. This is a pre-existing gap in vulnbot
			// itself, not something introduced here - it's simply never
			// surfaced before because SlackReporter's team report doesn't use
			// AffectedRepos at all. Compute it directly from the real repos
			// instead, the same workaround already used for
			// GetTeamSeverityBreakdown().
			findingSummary := FindingSummary{
				TotalCount:       summary.TotalCount,
				AffectedRepos:    getTeamAffectedRepoCount(repos),
				VulnsByEcosystem: summary.VulnsByEcosystem,
				VulnsBySeverity:  repos.GetTeamSeverityBreakdown(),
			}

			rowTitle := fmt.Sprintf("%s — %s", team.Name, reportTime.Format(DATE_LAYOUT))
			rowProps := buildHistoryRowProperties(rowTitle, team.Name, findingSummary, reportTime)
			// Each run's row gets this team's own affected-repo/finding detail
			// embedded in its page body, so historical rows are a full
			// snapshot of what was found that run - not just numeric columns.
			// Unlike the persistent page below, the row only lists repos that
			// actually have findings (see reposWithFindings): it's a record of
			// what was flagged, not a full roster.
			rowBlocks, rowRepos := buildRepoToggleBlocks(reposWithFindings(repos))

			rowPageID, err := n.Client.CreateDatabaseRow(n.Config.Notion_database_id, rowProps, rowBlocks)
			if err != nil {
				log.Error().Err(err).Str("team", team.Name).Msg("Failed to write Notion history row for team.")
			} else {
				n.attachSeverityFindings(rowPageID, rowRepos)
			}
		}

		if team.Notion_page_id == "" {
			log.Debug().Str("team", team.Name).Msg("Skipping Notion team page since Notion_page_id is not configured.")
			continue
		}

		// The persistent page lists every repo the team owns, clean or
		// not - pageRepos is a different (longer) list than rowRepos
		// above, since it isn't pre-filtered to only findings.
		pageBlocks, pageRepos := buildTeamPageBlocks(team, repos, reportTime)
		if err := n.Client.ReplacePageContent(team.Notion_page_id, pageBlocks); err != nil {
			log.Error().Err(err).Str("team", team.Name).Msg("Failed to refresh Notion team page.")
		} else {
			n.attachSeverityFindings(team.Notion_page_id, pageRepos)
		}
	}

	return nil
}

// SendRepoOwnershipReport syncs a repo ownership registry database: one
// row per non-archived repo in the org, showing which team(s) own it (or
// an "Unowned" tag if none do). Unlike the vulnerability-listings database
// (an append-only history, one row per run), this is kept as a LIVE
// SNAPSHOT - repos no longer present get their row archived away, existing
// repos get their row updated in place, and only genuinely new repos get
// created, so the table always reflects current reality rather than
// accumulating one entry per repo per run.
//
// This is NOT part of the Reporter interface, and isn't called from
// internal/scan.go's normal per-reporter dispatch loop the way
// SendSummaryReport/SendTeamReports are - it needs the full, unfiltered
// project list (every non-archived repo, whether or not any team owns
// it), which the standard interface never carries. GroupTeamFindings only
// ever assigns a project to a team that actually owns it, so a repo with
// zero owners never reaches TeamSummaries, and SendSummaryReport only ever
// sees aggregate numbers, not per-repo ownership. See the implementation
// guidelines for the full reasoning and how this gets dispatched instead.
//
// projects should be the raw, unfiltered project list - e.g.
// querying.ProjectCollection.Projects - not anything already grouped or
// filtered by ownership.
func (n *NotionReporter) SendRepoOwnershipReport(projects []*querying.Project, wg *sync.WaitGroup) error {
	defer wg.Done()
	log := logger.Get()

	if n.Client == nil {
		log.Warn().Msg("No Notion client available. Repo ownership report not sent.")
		return nil
	}
	if n.Config.Notion_ownership_database_id == "" {
		log.Debug().Msg("Skipping Notion repo ownership report since Notion_ownership_database_id is not configured.")
		return nil
	}

	databaseID := n.Config.Notion_ownership_database_id
	existingRows, err := n.Client.QueryDatabaseTitles(databaseID)
	if err != nil {
		log.Error().Err(err).Msg("Failed to query existing Notion repo ownership rows; skipping sync for this run.")
		return nil
	}

	seen := make(map[string]bool, len(projects))
	for _, project := range projects {
		seen[project.Name] = true
		properties := buildOwnershipRowProperties(project)

		if pageID, exists := existingRows[project.Name]; exists {
			if err := n.Client.UpdatePageProperties(pageID, properties); err != nil {
				log.Error().Err(err).Str("repo", project.Name).Msg("Failed to update Notion repo ownership row.")
			}
			continue
		}

		if _, err := n.Client.CreateDatabaseRow(databaseID, properties, nil); err != nil {
			log.Error().Err(err).Str("repo", project.Name).Msg("Failed to create Notion repo ownership row.")
		}
	}

	// Anything left in existingRows wasn't in this run's project list at
	// all - archived, renamed, or otherwise gone - so its row is stale.
	for name, pageID := range existingRows {
		if seen[name] {
			continue
		}
		if err := n.Client.ArchivePage(pageID); err != nil {
			log.Error().Err(err).Str("repo", name).Msg("Failed to archive stale Notion repo ownership row.")
		}
	}

	return nil
}