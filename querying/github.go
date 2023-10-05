package querying

import (
	"context"
	"sync"

	"github.com/shurcooL/githubv4"
	"github.com/underdog-tech/vulnbot/config"
	"github.com/underdog-tech/vulnbot/logger"
	"golang.org/x/oauth2"
)

type githubClient interface {
	Query(context.Context, interface{}, map[string]interface{}) error
}

// GithubDataSource is used to pull Dependabot alerts for an individual organization.
type GithubDataSource struct {
	GhClient githubClient
	orgName  string
	conf     config.Config
	ctx      context.Context
}

func NewGithubDataSource(conf config.Config, env config.Env) GithubDataSource {
	ghTokenSource := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: env.GithubToken},
	)
	httpClient := oauth2.NewClient(context.Background(), ghTokenSource)
	ghClient := githubv4.NewClient(httpClient)

	return GithubDataSource{
		GhClient: ghClient,
		orgName:  env.GithubOrg,
		conf:     conf,
		ctx:      context.Background(),
	}
}

type githubVulnerability struct {
	SecurityAdvisory struct {
		Description string
		Identifiers []struct {
			Type  string
			Value string
		}
	}
	SecurityVulnerability struct {
		Severity string
		Package  struct {
			Ecosystem string
			Name      string
		}
	}
}

type orgRepo struct {
	Name                string
	Url                 string
	VulnerabilityAlerts struct {
		TotalCount int
		PageInfo   struct {
			EndCursor   githubv4.String
			HasNextPage bool
		}
		Nodes []githubVulnerability
	} `graphql:"vulnerabilityAlerts(states: OPEN, first: 100, after: $alertCursor)"`
}

type repositoryQuery struct {
	Repository orgRepo `graphql:"repository(name: $repoName, owner: $orgName)"`
}

type orgVulnerabilityQuery struct {
	Organization struct {
		Name         string
		Login        string
		Repositories struct {
			TotalCount int
			PageInfo   struct {
				EndCursor   githubv4.String
				HasNextPage bool
			}
			Nodes []orgRepo
		} `graphql:"repositories(orderBy: {field: NAME, direction: ASC}, isFork: false, isArchived: false, first: 100, after: $repoCursor)"`
	} `graphql:"organization(login: $login)"`
}

// Ref: https://docs.github.com/en/graphql/reference/enums#securityadvisoryecosystem
var githubEcosystems = map[string]config.FindingEcosystemType{
	"ACTIONS":  config.FindingEcosystemGHA,
	"COMPOSER": config.FindingEcosystemPHP,
	"ERLANG":   config.FindingEcosystemErlang,
	"GO":       config.FindingEcosystemGo,
	"MAVEN":    config.FindingEcosystemJava,
	"NPM":      config.FindingEcosystemJS,
	"NUGET":    config.FindingEcosystemCSharp,
	"PIP":      config.FindingEcosystemPython,
	"PUB":      config.FindingEcosystemDart,
	"RUBYGEMS": config.FindingEcosystemRuby,
	"RUST":     config.FindingEcosystemRust,
	"SWIFT":    config.FindingEcosystemSwift,
}

var githubSeverities = map[string]config.FindingSeverityType{
	"CRITICAL": config.FindingSeverityCritical,
	"HIGH":     config.FindingSeverityHigh,
	"MODERATE": config.FindingSeverityModerate,
	"LOW":      config.FindingSeverityLow,
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
			err := gh.processRepoFindings(projects, repo, repo.VulnerabilityAlerts.PageInfo.EndCursor)
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

func (gh *GithubDataSource) processRepoFindings(projects *ProjectCollection, repo orgRepo, endCursor githubv4.String) error {
	log := logger.Get()
	project := projects.GetProject(repo.Name)
	project.Links["GitHub"] = repo.Url
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
		var repositoryQuery repositoryQuery
		queryVars := map[string]interface{}{
			"repoName":    githubv4.String(repo.Name),
			"orgName":     githubv4.String(gh.orgName),
			"alertCursor": githubv4.String(endCursor),
		}
		err := gh.GhClient.Query(gh.ctx, &repositoryQuery, queryVars)
		if err != nil {
			return err
		}

		nextCursor := repositoryQuery.Repository.VulnerabilityAlerts.PageInfo.EndCursor
		log.Info().Any("alertCursor", queryVars["alertCursor"]).Msg("Querying for more vulnerabilities for a repository.")
		return gh.processRepoFindings(projects, repositoryQuery.Repository, nextCursor)
	}

	return nil
}

type orgTeam struct {
	Name         string
	Slug         string
	Repositories struct {
		PageInfo struct {
			EndCursor   githubv4.String
			HasNextPage bool
		}
		Edges []struct {
			Permission string
			Node       struct {
				Name string
			}
		}
	} `graphql:"repositories(orderBy: {field: NAME, direction: ASC}, first: 100, after: $repoCursor)"`
}

type orgRepoOwnerQuery struct {
	Organization struct {
		Teams struct {
			TotalCount int
			PageInfo   struct {
				EndCursor   githubv4.String
				HasNextPage bool
			}
			Nodes []orgTeam
		} `graphql:"teams(orderBy: {field: NAME, direction: ASC}, first: 100, after: $teamCursor)"`
	} `graphql:"organization(login: $login)"`
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
		err := gh.GhClient.Query(gh.ctx, &ownerQuery, queryVars)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to query GitHub for repository ownership.")
		}
		for _, team := range ownerQuery.Organization.Teams.Nodes {
			teamConfig, err := config.GetTeamConfigBySlug(team.Slug, gh.conf.Team)
			if err != nil {
				log.Warn().Err(err).Str("slug", team.Slug).Msg("Failed to load team from config.")
				continue
			}
			// TODO: Handle pagination of repositories owned by a team
			for _, repo := range team.Repositories.Edges {
				switch repo.Permission {
				case "ADMIN", "MAINTAIN":
					project := projects.GetProject(repo.Node.Name)
					project.Owners.Add(teamConfig)
				default:
					continue
				}
			}
		}
		if !ownerQuery.Organization.Teams.PageInfo.HasNextPage {
			break
		}
		queryVars["teamCursor"] = githubv4.NewString(ownerQuery.Organization.Teams.PageInfo.EndCursor)
	}
}
