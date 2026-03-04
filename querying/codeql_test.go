package querying

import (
	"context"
	"iter"
	"maps"
	"sync"
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/google/go-github/v84/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/underdog-tech/vulnbot/configs"
)

const (
	mockOrgName  = "fake-org"
	mockTeamSlug = "fake-slug"
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
	mockDescription := "A pretty important alert"
	return &github.Alert{
		MostRecentInstance: &github.MostRecentInstance{
			Environment: &mockAlertEnv,
		},
		Repository: &github.Repository{Name: &mockRepo},
		Rule: &github.Rule{
			SecuritySeverityLevel: &mockSeverity,
			Description:           &mockDescription,
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

	mockTeam := getMockTeam()
	conf := &configs.Config{
		Team: []configs.TeamConfig{mockTeam},
	}
	mockClient := &MockClient{}
	testContext := context.Background()
	mockRepoMap := map[*github.Repository]error{
		{Name: &mockRepo}: nil,
	}
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
	mockClient.On("ListTeamReposBySlugIter", testContext, mockOrgName, mockTeamSlug, nil).Return(
		maps.All(mockRepoMap),
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
		Owners: mapset.NewSet(mockTeam),
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

func TestGetRepoNameToTeamConfig(t *testing.T) {
	mockRepo := "link"
	mockTeam := getMockTeam()
	conf := &configs.Config{
		Team: []configs.TeamConfig{mockTeam},
	}
	mockClient := &MockClient{}
	testContext := context.Background()
	mockRepoMap := map[*github.Repository]error{
		{Name: &mockRepo}: nil,
	}

	cql := &CodeQLDataSource{
		GhClient: mockClient,
		orgName:  mockOrgName,
		conf:     conf,
		ctx:      testContext,
	}

	mockClient.On("ListTeamReposBySlugIter", testContext, mockOrgName, mockTeamSlug, nil).Return(
		maps.All(mockRepoMap),
	)

	actualRepoNameToTeamConfig, err := cql.getRepoNameToTeamConfig()

	expectedRepoNameToTeamConfig := map[string]configs.TeamConfig{
		mockRepo: mockTeam,
	}
	assert.NoError(t, err)
	assert.Equal(t, expectedRepoNameToTeamConfig, actualRepoNameToTeamConfig)

	mockClient.AssertExpectations(t)
}
