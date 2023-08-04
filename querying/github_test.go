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
	"github.com/underdog-tech/vulnbot/config"
	"github.com/underdog-tech/vulnbot/querying"
)

func TestCollectFindingsSingleProjectSingleFinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var bodyJson map[string]string
		var data []byte
		_ = json.NewDecoder(r.Body).Decode(&bodyJson)
		vulnQuery := strings.Contains(bodyJson["query"], "vulnerabilityAlerts")
		if vulnQuery {
			data, _ = os.ReadFile("testdata/single_project_single_finding_vulns.json")
		} else {
			data, _ = os.ReadFile("testdata/single_project_single_finding_owners.json")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(data))
	}))
	defer server.Close()

	conf := config.Config{}
	env := config.Env{}
	env.GithubOrg = "heart-of-gold"
	env.GithubToken = "pangalactic-gargleblaster"

	ds := querying.NewGithubDataSource(conf, env)
	ds.GhClient = githubv4.NewEnterpriseClient(server.URL, &http.Client{})

	projects := querying.NewProjectCollection()
	wg := new(sync.WaitGroup)
	wg.Add(1)
	ds.CollectFindings(projects, wg)
	expected := querying.ProjectCollection{
		Projects: []*querying.Project{
			{
				Name: "zaphod",
				Links: map[string]string{
					"GitHub": "https://heart-of-gold/zaphod",
				},
				Findings: []*querying.Finding{
					{
						Ecosystem:   querying.FindingEcosystemGo,
						Severity:    querying.FindingSeverityCritical,
						Description: "The Improbability Drive is far too improbable.",
						PackageName: "improbability-drive",
						Identifiers: querying.FindingIdentifierMap{
							querying.FindingIdentifierCVE: "CVE-42",
						},
					},
				},
				Owners: mapset.NewSet[config.TeamConfig](),
			},
		},
	}
	assert.Equal(t, &expected, projects)
}
