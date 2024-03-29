package querying_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/shurcooL/githubv4"
	"github.com/stretchr/testify/assert"
	"github.com/underdog-tech/vulnbot/configs"
	"github.com/underdog-tech/vulnbot/querying"
)

func getTestServer(findingFile string, ownerFile string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var bodyJson map[string]string
		var data []byte
		_ = json.NewDecoder(r.Body).Decode(&bodyJson)
		vulnQuery := strings.Contains(bodyJson["query"], "vulnerabilityAlerts")
		if vulnQuery {
			data, _ = os.ReadFile(findingFile)
		} else {
			data, _ = os.ReadFile(ownerFile)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(data))
	}))
}

func getTestProject() querying.ProjectCollection {
	return querying.ProjectCollection{
		Projects: []*querying.Project{
			{
				Name: "zaphod",
				Link: "https://heart-of-gold/zaphod/security/dependabot",
				Findings: []*querying.Finding{
					{
						Ecosystem:   configs.FindingEcosystemGo,
						Severity:    configs.FindingSeverityCritical,
						Description: "The Improbability Drive is far too improbable.",
						PackageName: "improbability-drive",
						Identifiers: querying.FindingIdentifierMap{
							querying.FindingIdentifierCVE: "CVE-42",
						},
					},
				},
				Owners: mapset.NewSet[configs.TeamConfig](),
			},
		},
	}
}

func TestCollectFindingsSingleProjectSingleFinding(t *testing.T) {
	server := getTestServer(
		"testdata/single_project_single_finding_vulns.json",
		"testdata/single_project_no_owners.json",
	)
	defer server.Close()

	conf := configs.Config{}
	conf.Github_org = "heart-of-gold"
	conf.Github_token = "pangalactic-gargleblaster"

	ds := querying.NewGithubDataSource(&conf)
	ds.GhClient = githubv4.NewEnterpriseClient(server.URL, &http.Client{})

	projects := querying.NewProjectCollection()
	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := ds.CollectFindings(projects, wg)
	if err != nil {
		t.Error(err)
	}
	expected := getTestProject()
	assert.Equal(t, &expected, projects)
}

// TestCollectFindingsOwnerNotConfigured is nearly identical to TestCollectFindingsSingleProjectSingleFinding
// The only difference is that this test simulates receiving an owning team from GitHub
// which is not present in configs. This is to ensure that we don't end up with empty
// TeamConfig instances in our project owners set.
func TestCollectFindingsOwnerNotConfigured(t *testing.T) {
	server := getTestServer(
		"testdata/single_project_single_finding_vulns.json",
		"testdata/single_project_single_owner.json",
	)
	defer server.Close()

	conf := configs.Config{}
	conf.Github_org = "heart-of-gold"
	conf.Github_token = "pangalactic-gargleblaster"

	ds := querying.NewGithubDataSource(&conf)
	ds.GhClient = githubv4.NewEnterpriseClient(server.URL, &http.Client{})

	projects := querying.NewProjectCollection()
	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := ds.CollectFindings(projects, wg)
	if err != nil {
		t.Error(err)
	}
	expected := getTestProject()
	assert.Equal(t, &expected, projects)
}

func TestCollectFindingsOwnerIsConfigured(t *testing.T) {
	server := getTestServer(
		"testdata/single_project_single_finding_vulns.json",
		"testdata/single_project_single_owner.json",
	)
	defer server.Close()

	crewTeam := configs.TeamConfig{
		Name:        "Heart of Gold Crew",
		Github_slug: "crew",
	}
	conf := configs.Config{
		Team: []configs.TeamConfig{crewTeam},
	}
	conf.Github_org = "heart-of-gold"
	conf.Github_token = "pangalactic-gargleblaster"

	ds := querying.NewGithubDataSource(&conf)
	ds.GhClient = githubv4.NewEnterpriseClient(server.URL, &http.Client{})

	projects := querying.NewProjectCollection()
	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := ds.CollectFindings(projects, wg)
	if err != nil {
		t.Error(err)
	}
	owners := mapset.NewSet[configs.TeamConfig]()
	owners.Add(crewTeam)
	expected := getTestProject()
	expected.Projects[0].Owners = owners
	assert.Equal(t, &expected, projects)
}

func TestCollectFindingsMultipleFindings(t *testing.T) {
	server := getTestServer(
		"testdata/single_project_multiple_findings.json",
		"testdata/single_project_no_owners.json",
	)
	defer server.Close()

	conf := configs.Config{}
	conf.Github_org = "heart-of-gold"
	conf.Github_token = "pangalactic-gargleblaster"

	ds := querying.NewGithubDataSource(&conf)
	ds.GhClient = githubv4.NewEnterpriseClient(server.URL, &http.Client{})

	projects := querying.NewProjectCollection()
	wg := new(sync.WaitGroup)
	wg.Add(1)
	err := ds.CollectFindings(projects, wg)
	if err != nil {
		t.Error(err)
	}
	expected := getTestProject()
	finding2 := querying.Finding{
		Ecosystem:   configs.FindingEcosystemPython,
		Severity:    configs.FindingSeverityModerate,
		Description: "All the dolphins are leaving.",
		PackageName: "dolphins",
		Identifiers: querying.FindingIdentifierMap{
			querying.FindingIdentifierCVE: "CVE-43",
		},
	}
	expected.Projects[0].Findings = append(expected.Projects[0].Findings, &finding2)
	assert.Equal(t, &expected, projects)

}
