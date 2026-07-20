package querying

import (
	"context"
	"fmt"
	"iter"
	"maps"
	"sync"
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/google/go-github/v84/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/underdog-tech/vulnbot/configs"
	"github.com/underdog-tech/vulnbot/logger"
)

const (
	mockOrgName      = "fake-org"
	mockTeamSlug     = "fake-slug"
	mockDescription  = "A pretty important alert"
	mockRepoUrl      = "https://github.com/underdog-tech/link"
	mockSecurityPath = "security"
)

type MockClient struct {
	mock.Mock
}

func (m *MockClient) ListAlertsForOrgIter(ctx context.Context, org string, opts *github.AlertListOptions) iter.Seq2[*github.Alert, error] {
	args := m.Called(ctx, org, opts)
	return args.Get(0).(iter.Seq2[*github.Alert, error])
}

func (m *MockClient) ListTeamReposBySlugIter(ctx context.Context, org string, slug string, opts *github.ListOptions) iter.Seq2[*github.Repository, error] {
	args := m.Called(ctx, org, slug, nil)
	return args.Get(0).(iter.Seq2[*github.Repository, error])
}

func getMockAlert() *github.Alert {
	mockRepo := "link"
	mockAlertEnv := "{\"build-mode\":\"none\",\"category\":\"/language:python\",\"language\":\"python\",\"runner\":\"[\\\"ubuntu-latest\\\"]\"}"
	mockSeverity := "high"
	mockDescriptionVar := mockDescription
	mockRepoUrlVar := mockRepoUrl
	return &github.Alert{
		MostRecentInstance: &github.MostRecentInstance{
			Environment: &mockAlertEnv,
		},
		Repository: &github.Repository{Name: &mockRepo, HTMLURL: &mockRepoUrlVar},
		Rule: &github.Rule{
			SecuritySeverityLevel: &mockSeverity,
			Description:           &mockDescriptionVar,
		},
	}
}

func getMockTeam() configs.TeamConfig {
	return configs.TeamConfig{
		Name:        "Team One",
		Github_slug: mockTeamSlug,
	}
}

func TestCollectFindings(t *testing.T) {
	mockRepo := "link"
	mockDescription := "A pretty important alert"

	adminTeam := getMockTeam()
	maintainTeam := configs.TeamConfig{Name: "Team Two", Github_slug: "team-two"}
	conf := &configs.Config{
		Team: []configs.TeamConfig{adminTeam, maintainTeam},
	}
	mockClient := &MockClient{}
	testContext := context.Background()
	mockAlert := getMockAlert()
	mockAlertsByOrg := map[*github.Alert]error{mockAlert: nil}

	cql := &CodeQLDataSource{
		GhClient: mockClient,
		orgName:  mockOrgName,
		conf:     conf,
		ctx:      testContext,
	}

	mockClient.On("ListAlertsForOrgIter", testContext, mockOrgName, &github.AlertListOptions{State: Open}).Return(
		maps.All(mockAlertsByOrg),
	)
	mockClient.On("ListTeamReposBySlugIter", testContext, mockOrgName, adminTeam.Github_slug, nil).Return(
		maps.All(map[*github.Repository]error{
			{Name: &mockRepo, Permissions: &github.RepositoryPermissions{Admin: github.Ptr(true)}}: nil,
		}),
	)
	mockClient.On("ListTeamReposBySlugIter", testContext, mockOrgName, maintainTeam.Github_slug, nil).Return(
		maps.All(map[*github.Repository]error{
			{Name: &mockRepo, Permissions: &github.RepositoryPermissions{Maintain: github.Ptr(true)}}: nil,
		}),
	)

	expectedProject := &Project{
		Name: mockRepo,
		Findings: []*Finding{
			{
				Description: mockDescription,
				Ecosystem:   configs.FindingEcosystemPython,
				Severity:    configs.FindingSeverityHigh,
			},
		},
		Link:   fmt.Sprintf("%s/%s", mockRepoUrl, mockSecurityPath),
		Owners: mapset.NewSet(adminTeam, maintainTeam),
	}
	mockProjects := &ProjectCollection{}
	wg := new(sync.WaitGroup)
	wg.Add(1)

	err := cql.CollectFindings(mockProjects, wg)

	assert.NoError(t, err)
	assert.Equal(t, mockProjects.Projects[0], expectedProject)
}

func TestProcessFinding(t *testing.T) {
	mockDescription := "A pretty important alert"
	expectedFinding := &Finding{
		Description: mockDescription,
		Ecosystem:   configs.FindingEcosystemPython,
		Severity:    configs.FindingSeverityHigh,
	}
	conf := &configs.Config{}
	mockClient := &MockClient{}
	testContext := context.Background()
	cql := &CodeQLDataSource{
		GhClient: mockClient,
		orgName:  mockOrgName,
		conf:     conf,
		ctx:      testContext,
	}

	mockAlert := getMockAlert()

	finding, err := cql.processFinding(mockAlert)

	assert.NoError(t, err)
	assert.Equal(t, expectedFinding, finding)
}

func TestGetRepoNameToTeamConfigs(t *testing.T) {
	testLogger := logger.Get()
	mockRepo := "link"
	adminTeam := getMockTeam()
	maintainTeam := configs.TeamConfig{Name: "Team Two", Github_slug: "team-two"}
	pushTeam := configs.TeamConfig{Name: "Team Three", Github_slug: "team-three"}
	testContext := context.Background()

	tests := map[string][]configs.TeamConfig{
		"configured order":          {adminTeam, maintainTeam, pushTeam},
		"reversed configured order": {pushTeam, maintainTeam, adminTeam},
	}
	for name, teams := range tests {
		t.Run(name, func(t *testing.T) {
			conf := &configs.Config{Team: teams}
			mockClient := &MockClient{}
			cql := &CodeQLDataSource{
				GhClient: mockClient,
				orgName:  mockOrgName,
				conf:     conf,
				ctx:      testContext,
			}

			teamRepos := map[string]*github.Repository{
				adminTeam.Github_slug: {
					Name:        &mockRepo,
					Permissions: &github.RepositoryPermissions{Admin: github.Ptr(true)},
				},
				maintainTeam.Github_slug: {
					Name:        &mockRepo,
					Permissions: &github.RepositoryPermissions{Maintain: github.Ptr(true)},
				},
				pushTeam.Github_slug: {
					Name:        &mockRepo,
					Permissions: &github.RepositoryPermissions{Push: github.Ptr(true)},
				},
			}
			for _, team := range teams {
				mockClient.On("ListTeamReposBySlugIter", testContext, mockOrgName, team.Github_slug, nil).Return(
					maps.All(map[*github.Repository]error{teamRepos[team.Github_slug]: nil}),
				)
			}

			actualRepoNameToTeamConfigs := cql.getRepoNameToTeamConfigs(testLogger)

			expectedRepoNameToTeamConfigs := map[string]mapset.Set[configs.TeamConfig]{
				mockRepo: mapset.NewSet(adminTeam, maintainTeam),
			}
			assert.Equal(t, expectedRepoNameToTeamConfigs, actualRepoNameToTeamConfigs)
			mockClient.AssertExpectations(t)
		})
	}
}
