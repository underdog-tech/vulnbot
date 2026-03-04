package querying

import (
	"context"
	"strings"
	"sync"

	"golang.org/x/oauth2"

	"github.com/rs/zerolog"
	"github.com/shurcooL/githubv4"
	"github.com/underdog-tech/vulnbot/configs"
	"github.com/underdog-tech/vulnbot/logger"
)

const DisableVulnBotTopicKeyword = "disable-vulnbot"

type githubClient interface {
	Query(context.Context, interface{}, map[string]interface{}) error
}

// GithubDataSource is used to pull Dependabot alerts for an individual organization.
type GithubDataSource struct {
	GhClient githubClient
	orgName  string
	conf     *configs.Config
	ctx      context.Context
}

func NewGithubDataSource(conf *configs.Config) GithubDataSource {
	ghTokenSource := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: conf.Github_token},
	)
	httpClient := oauth2.NewClient(context.Background(), ghTokenSource)
	ghClient := githubv4.NewClient(httpClient)

	return GithubDataSource{
		GhClient: ghClient,
		orgName:  conf.Github_org,
		conf:     conf,
		ctx:      context.Background(),
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

	// Link directly to Dependabot findings.
	// There doesn't appear to be a GraphQL property for this link.
	project.Link = repo.Url + "/security/dependabot"

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
			shouldIgnoreRepo := repo.Node.IsArchived || repo.Node.IsFork || hasDisableVulnbotTopic(repo.Node.RepositoryTopics)
			if shouldIgnoreRepo {
				log.Debug().
					Str("Repo", repo.Node.Name).
					Bool("IsFork", repo.Node.IsFork).
					Bool("IsArchived", repo.Node.IsArchived).
					Msg("Skipping untracked repository.")
				continue
			}
			switch repo.Permission {
			case "ADMIN", "MAINTAIN":
				project := projects.GetProject(repo.Node.Name)
				project.Owners.Add(teamConfig)
			default:
				continue
			}
		}
	}
}

// Function to check if the repository has "disable-vulnbot" in its topics
func hasDisableVulnbotTopic(repoTopics repositoryTopics) bool {
	for _, edge := range repoTopics.Edges {
		if strings.Contains(strings.ToLower(edge.Node.Topic.Name), DisableVulnBotTopicKeyword) {
			return true
		}
	}
	return false
}
