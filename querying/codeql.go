package querying

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"sync"

	mapset "github.com/deckarep/golang-set/v2"
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

	repoNameToTeamConfigs := cql.getRepoNameToTeamConfigs(log)

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

		teams, ok := repoNameToTeamConfigs[*alert.Repository.Name]
		if !ok {
			log.Warn().Str("repository", *alert.Repository.Name).Msg("Failed to find team config in repository team map")
			continue
		}
		teamIter := teams.Iterator()
		for team := range teamIter.C {
			project.Owners.Add(team)
		}
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

// Maps repository names to all configured teams with administrative or maintenance access.
func (cql *CodeQLDataSource) getRepoNameToTeamConfigs(log zerolog.Logger) map[string]mapset.Set[configs.TeamConfig] {
	repoNameToTeamConfigs := make(map[string]mapset.Set[configs.TeamConfig])
	for _, team := range cql.conf.Team {
		slugIter := cql.GhClient.ListTeamReposBySlugIter(cql.ctx, cql.orgName, team.Github_slug, nil)
		for repo, err := range slugIter {
			if err != nil {
				log.Error().Err(err).Str("team_name", team.Name).Msg("Failed to find owned repos for team")
				continue
			}
			if shouldIgnoreRepository(repo.GetArchived(), repo.GetFork(), repo.Topics) {
				log.Debug().
					Str("repository", repo.GetName()).
					Bool("is_fork", repo.GetFork()).
					Bool("is_archived", repo.GetArchived()).
					Msg("Skipping untracked repository.")
				continue
			}
			if repo.Permissions == nil || (!repo.Permissions.GetAdmin() && !repo.Permissions.GetMaintain()) {
				continue
			}
			if _, ok := repoNameToTeamConfigs[repo.GetName()]; !ok {
				repoNameToTeamConfigs[repo.GetName()] = mapset.NewSet[configs.TeamConfig]()
			}
			repoNameToTeamConfigs[repo.GetName()].Add(team)
		}
	}
	return repoNameToTeamConfigs
}
