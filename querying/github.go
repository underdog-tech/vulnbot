package querying

import (
	"context"
	"sync"

	"golang.org/x/oauth2"

	"github.com/rs/zerolog"
	"github.com/shurcooL/githubv4"
	"github.com/underdog-tech/vulnbot/configs"
	"github.com/underdog-tech/vulnbot/logger"
)

type githubClient interface {
	Query(context.Context, interface{}, map[string]interface{}) error
}

// GithubDataSource is used to pull Dependabot alerts for an individual organization.
type GithubDataSource struct {
	GhClient githubClient
	orgName  string
	conf     *configs.Config
	ctx      context.Context

	// ForkProjects collects forked repos that have an owning team, kept
	// entirely separate from the main ProjectCollection passed into
	// CollectFindings. Forks are deliberately excluded from vulnerability
	// scanning (see orgVulnerabilityQuery's isFork: false filter below,
	// and shouldIgnoreRepository's isFork check), but ownership can still
	// be tracked for them - this exists specifically so that ownership
	// tracking (e.g. a Notion ownership registry) can see forks without
	// them leaking into vulnerability-facing reporting (SummarizeFindings,
	// GroupTeamFindings, and therefore Slack/Console/Notion vulnerability
	// output), which never reads this field. Populated as a side effect of
	// gatherRepoOwners, reusing the same team-repository query rather than
	// a second round trip - see processRepoOwners.
	ForkProjects *ProjectCollection
}

func NewGithubDataSource(conf *configs.Config) GithubDataSource {
	ghTokenSource := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: conf.Github_token},
	)
	httpClient := oauth2.NewClient(context.Background(), ghTokenSource)
	ghClient := githubv4.NewClient(httpClient)

	return GithubDataSource{
		GhClient:     ghClient,
		orgName:      conf.Github_org,
		conf:         conf,
		ctx:          context.Background(),
		ForkProjects: NewProjectCollection(),
	}
}

// Ref: https://docs.github.com/en/graphql/reference/enums#securityadvisoryecosystem
var githubEcosystems = map[string]configs.FindingEcosystemType{
	"ACTIONS":  configs.FindingEcosystemGHA,
	"COMPOSER": configs.FindingEcosystemPHP,
	"ERLANG":   configs.FindingEcosystemErlang,
	"GO":       configs.FindingEcosystemGo,
	"MAVEN":    configs.FindingEcosystemJava,
	"NPM":      configs.FindingEcosystemJS,
	"NUGET":    configs.FindingEcosystemCSharp,
	"PIP":      configs.FindingEcosystemPython,
	"PUB":      configs.FindingEcosystemDart,
	"RUBYGEMS": configs.FindingEcosystemRuby,
	"RUST":     configs.FindingEcosystemRust,
	"SWIFT":    configs.FindingEcosystemSwift,
}

var githubSeverities = map[string]configs.FindingSeverityType{
	"CRITICAL": configs.FindingSeverityCritical,
	"HIGH":     configs.FindingSeverityHigh,
	"MODERATE": configs.FindingSeverityModerate,
	"LOW":      configs.FindingSeverityLow,
}

func (gh *GithubDataSource) CollectFindings(projects *ProjectCollection, wg *sync.WaitGroup) error {
	var alertQuery orgVulnerabilityQuery
	log := logger.Get()
	defer wg.Done()

	queryVars := map[string]interface{}{
		"login":       githubv4.String(gh.orgName),
		"repoCursor":  (*githubv4.String)(nil), // We pass nil/null to get the first page
		"alertCursor": (*githubv4.String)(nil),
	}

	for {
		log.Info().Any("repoCursor", queryVars["repoCursor"]).Msg("Querying GitHub API for repositories with vulnerabilities.")
		err := gh.GhClient.Query(gh.ctx, &alertQuery, queryVars)
		if err != nil {
			log.Error().Err(err).Msg("GitHub repository query failed!")
			return err
		}
		for _, repo := range alertQuery.Organization.Repositories.Nodes {
			err := gh.processRepoFindings(projects, repo)
			if err != nil {
				log.Warn().Err(err).Str("repository", repo.Name).Msg("Failed to process findings for repository.")
			}
		}

		if !alertQuery.Organization.Repositories.PageInfo.HasNextPage {
			break
		}
		queryVars["repoCursor"] = githubv4.NewString(alertQuery.Organization.Repositories.PageInfo.EndCursor)
	}
	gh.gatherRepoOwners(projects)
	return nil
}

func (gh *GithubDataSource) processRepoFindings(projects *ProjectCollection, repo orgRepo) error {
	log := logger.Get()
	project := projects.GetProject(repo.Name)

	// Link directly to security page.
	// There doesn't appear to be a GraphQL property for this link.
	project.Link = repo.Url + "/security"
	// Every repo reaching this method came from orgVulnerabilityQuery,
	// which already filters isFork: false at the GraphQL level - so this
	// is always accurate, not just a default.
	project.IsFork = false
	project.Visibility = repo.Visibility

	log.Debug().Str("project", project.Name).Msg("Processing findings for project.")

	for _, vuln := range repo.VulnerabilityAlerts.Nodes {
		identifiers := FindingIdentifierMap{}
		for _, id := range vuln.SecurityAdvisory.Identifiers {
			identifiers[FindingIdentifierType(id.Type)] = id.Value
		}
		log.Debug().Any("identifiers", identifiers).Msg("Processing finding.")
		// Utilizing a lambda to account for locks/deferrals
		func() {
			finding := project.GetFinding(identifiers)
			finding.mu.Lock()
			defer finding.mu.Unlock()

			if finding.Description == "" {
				finding.Description = vuln.SecurityAdvisory.Description
			}
			if finding.Ecosystem == "" {
				finding.Ecosystem = githubEcosystems[vuln.SecurityVulnerability.Package.Ecosystem]
			}
			if finding.PackageName == "" {
				finding.PackageName = vuln.SecurityVulnerability.Package.Name
			}
			finding.Severity = githubSeverities[vuln.SecurityVulnerability.Severity]
		}()
	}

	if repo.VulnerabilityAlerts.PageInfo.HasNextPage {
		var repoQuery repositoryQuery
		queryVars := map[string]interface{}{
			"repoName":    githubv4.String(repo.Name),
			"orgName":     githubv4.String(gh.orgName),
			"alertCursor": githubv4.String(repo.VulnerabilityAlerts.PageInfo.EndCursor),
		}
		err := gh.GhClient.Query(gh.ctx, &repoQuery, queryVars)
		if err != nil {
			return err
		}

		log.Info().Str("repoName", repo.Name).Any("alertCursor", queryVars["alertCursor"]).Msg("Querying for more vulnerabilities for a repository.")
		return gh.processRepoFindings(projects, repoQuery.Repository)
	}

	return nil
}

func (gh *GithubDataSource) gatherRepoOwners(projects *ProjectCollection) {
	var ownerQuery orgRepoOwnerQuery
	log := logger.Get()

	queryVars := map[string]interface{}{
		"login":      githubv4.String(gh.orgName),
		"repoCursor": (*githubv4.String)(nil), // We pass nil/null to get the first page
		"teamCursor": (*githubv4.String)(nil),
	}

	for {
		log.Info().Msg("Querying GitHub API for repository ownership information.")
		if err := gh.queryRepoOwners(&ownerQuery, queryVars); err != nil {
			log.Fatal().Err(err).Msg("Failed to query GitHub for repository ownership.")
		}

		gh.processRepoOwners(&ownerQuery, projects, log)
		if !ownerQuery.Organization.Teams.PageInfo.HasNextPage {
			break
		}
		queryVars["teamCursor"] = githubv4.NewString(ownerQuery.Organization.Teams.PageInfo.EndCursor)
	}
}

func (gh *GithubDataSource) queryRepoOwners(ownerQuery *orgRepoOwnerQuery, queryVars map[string]interface{}) error {
	if err := gh.GhClient.Query(gh.ctx, ownerQuery, queryVars); err != nil {
		return err
	}
	return nil
}

func (gh *GithubDataSource) processRepoOwners(ownerQuery *orgRepoOwnerQuery, projects *ProjectCollection, log zerolog.Logger) {
	for _, team := range ownerQuery.Organization.Teams.Nodes {
		teamConfig, err := configs.GetTeamConfigBySlug(team.Slug, gh.conf.Team)
		if err != nil {
			log.Warn().Err(err).Str("slug", team.Slug).Msg("Failed to load team from configs.")
			continue
		}
		for _, repo := range team.Repositories.Edges {
			// isFork is intentionally passed as false here, regardless of
			// the repo's actual fork status: shouldIgnoreRepository's
			// archived/disable-topic checks should still fully exclude a
			// repo (from everywhere, including ForkProjects below), but
			// whether it's a fork is handled separately just below,
			// rather than folded into this one ignore/don't-ignore check.
			if shouldIgnoreRepository(
				repo.Node.IsArchived,
				false,
				repo.Node.RepositoryTopics.names(),
			) {
				log.Debug().
					Str("Repo", repo.Node.Name).
					Bool("IsArchived", repo.Node.IsArchived).
					Msg("Skipping untracked repository.")
				continue
			}
			switch repo.Permission {
			case "ADMIN", "MAINTAIN":
				if repo.Node.IsFork {
					// Ownership-registry-only - see ForkProjects' comment
					// for why this is kept separate from the main
					// ProjectCollection instead of just being included.
					forkProject := gh.ForkProjects.GetProject(repo.Node.Name)
					forkProject.Link = repo.Node.Url + "/security"
					forkProject.IsFork = true
					forkProject.Visibility = repo.Node.Visibility
					forkProject.Owners.Add(teamConfig)
					continue
				}
				project := projects.GetProject(repo.Node.Name)
				project.Owners.Add(teamConfig)
				// Defensive, not strictly required: a non-fork repo
				// reaching here should already have IsFork/Visibility set
				// by processRepoFindings earlier in the same
				// CollectFindings call (the vulnerability-alerts pass
				// runs first). Setting them again here too means this
				// stays correct even if that ordering assumption ever
				// changes.
				project.IsFork = false
				project.Visibility = repo.Node.Visibility
			default:
				continue
			}
		}
	}
}