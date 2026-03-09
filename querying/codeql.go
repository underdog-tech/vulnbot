package querying

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"sync"

	"github.com/google/go-github/v84/github"
	"github.com/rs/zerolog"

	"github.com/underdog-tech/vulnbot/configs"
	"github.com/underdog-tech/vulnbot/logger"
)

const Open = "open"

type CodeQLEnvironment struct {
	Language string `json:"language"`
}

type Client interface {
	ListAlertsForOrgIter(ctx context.Context, org string, opts *github.AlertListOptions) iter.Seq2[*github.Alert, error]
	ListTeamReposBySlugIter(ctx context.Context, org string, slug string, opts *github.ListOptions) iter.Seq2[*github.Repository, error]
}

type GhClient struct {
	client *github.Client
}

func (g *GhClient) ListAlertsForOrgIter(ctx context.Context, org string, opts *github.AlertListOptions) iter.Seq2[*github.Alert, error] {
	return g.client.CodeScanning.ListAlertsForOrgIter(ctx, org, opts)
}

func (g *GhClient) ListTeamReposBySlugIter(ctx context.Context, org string, slug string, opts *github.ListOptions) iter.Seq2[*github.Repository, error] {
	return g.client.Teams.ListTeamReposBySlugIter(ctx, org, slug, opts)
}

type CodeQLDataSource struct {
	GhClient Client
	orgName  string
	conf     *configs.Config
	ctx      context.Context
}

func NewCodeQLDataSource(conf *configs.Config) CodeQLDataSource {
	return CodeQLDataSource{
		GhClient: &GhClient{
			client: github.NewClient(nil).WithAuthToken(conf.Github_token),
		},
		orgName: conf.Github_org,
		conf:    conf,
		ctx:     context.Background(),
	}
}

// Queries the org for all CodeQL alerts and processes them as Finding objects within individual Project objects.
// In addition we determine the team owner of each project if we do not have it yet.
func (cql *CodeQLDataSource) CollectFindings(projects *ProjectCollection, wg *sync.WaitGroup) error {
	log := logger.Get()
	defer wg.Done()

	repoNameToTeamConfig := cql.getRepoNameToTeamConfig(log)

	iter := cql.GhClient.ListAlertsForOrgIter(
		cql.ctx,
		cql.orgName,
		&github.AlertListOptions{State: Open},
	)

	for alert, err := range iter {
		if err != nil {
			log.Error().Err(err).Msg("GitHub list alerts request failed!")
			return err
		}

		finding, err := cql.processFinding(alert)
		if err != nil {
			log.Error().Err(err).Msg("Failed to process alert")
			return err
		}

		project := projects.GetProject(*alert.Repository.Name)
		project.Findings = append(project.Findings, finding)
		project.Link = fmt.Sprintf("%s/%s", *alert.Repository.HTMLURL, "security")

		team, ok := repoNameToTeamConfig[*alert.Repository.Name]
		if !ok {
			log.Warn().Err(err).Str("repository", *alert.Repository.Name).Msg("Failed to find team config in repository team map")
			continue
		}
		project.Owners.Add(team)
	}

	return nil
}

func (cql *CodeQLDataSource) processFinding(alert *github.Alert) (*Finding, error) {
	codeQLEnv := &CodeQLEnvironment{}
	if err := json.Unmarshal([]byte(*alert.MostRecentInstance.Environment), codeQLEnv); err != nil {
		return nil, err
	}
	return &Finding{
		Description: *alert.Rule.Description,
		Severity: configs.FindingSeverityType(
			configs.SeverityString[*alert.Rule.SecuritySeverityLevel],
		),
		Ecosystem: configs.FindingEcosystemType(codeQLEnv.Language),
	}, nil
}

// Maps repository names to their corresponding team configs based on the GH team slug.
func (cql *CodeQLDataSource) getRepoNameToTeamConfig(log zerolog.Logger) map[string]configs.TeamConfig {
	repoNameToTeamConfig := make(map[string]configs.TeamConfig)
	for _, team := range cql.conf.Team {
		slugIter := cql.GhClient.ListTeamReposBySlugIter(cql.ctx, cql.orgName, team.Github_slug, nil)
		for repo, err := range slugIter {
			if err != nil {
				log.Error().Err(err).Str("team_name", team.Name).Msg("Failed to find owned repos for team")
			} else {
				repoNameToTeamConfig[*repo.Name] = team
			}
		}
	}
	return repoNameToTeamConfig
}
