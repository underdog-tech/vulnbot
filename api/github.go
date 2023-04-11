package api

import (
	"context"
	"vulnbot/logger"

	"github.com/shurcooL/githubv4"
)

type VulnerabilityAlert struct {
	Id                    string
	Number                int
	SecurityVulnerability struct {
		Severity string
		Package  struct {
			Ecosystem string
			Name      string
		}
	}
}

type VulnerabilityRepository struct {
	Name                string
	IsArchived          bool
	VulnerabilityAlerts struct {
		TotalCount int
		Nodes      []VulnerabilityAlert
	} `graphql:"vulnerabilityAlerts(first: 100, states: OPEN)"`
}

type OrgVulnerabilityQuery struct {
	Organization struct {
		Name         string
		Login        string
		Repositories struct {
			TotalCount int
			PageInfo   struct {
				EndCursor   githubv4.String
				HasNextPage bool
			}
			Nodes []VulnerabilityRepository
		} `graphql:"repositories(orderBy: {field: NAME, direction: ASC}, isFork: false, first: 100, after: $reposCursor)"`
	} `graphql:"organization(login: $login)"`
}

func QueryGithubOrgVulnerabilities(ghOrgLogin string, ghClient githubv4.Client) (orgName string, repositories []VulnerabilityRepository) {
	var alertQuery OrgVulnerabilityQuery
	log := logger.Get()

	// Construct the variables necessary for our GraphQL query
	queryVars := map[string]interface{}{
		"login":       githubv4.String(ghOrgLogin),
		"reposCursor": (*githubv4.String)(nil), // Null after argument to get first page
	}

	// Gather all repositories, handling pagination
	var allRepos []VulnerabilityRepository
	for {
		log.Info().Msg("Querying GitHub API for vulnerable repositories.")
		err := ghClient.Query(context.Background(), &alertQuery, queryVars)
		if err != nil {
			log.Panic().Err(err).Msg("Failed to query GitHub!")
		}
		allRepos = append(allRepos, alertQuery.Organization.Repositories.Nodes...)
		if !alertQuery.Organization.Repositories.PageInfo.HasNextPage {
			break
		}
		// TODO: Handle pagination of vulnerabilities in a repository
		queryVars["reposCursor"] = githubv4.NewString(alertQuery.Organization.Repositories.PageInfo.EndCursor)
	}

	return alertQuery.Organization.Name, allRepos
}

type orgTeamNode struct {
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
	} `graphql:"repositories(orderBy: {field: NAME, direction: ASC}, first: 100, after: $reposCursor)"`
}

type orgRepositoryOwnerQuery struct {
	Organization struct {
		Teams struct {
			TotalCount int
			PageInfo   struct {
				EndCursor   githubv4.String
				HasNextPage bool
			}
			Nodes []orgTeamNode
		} `graphql:"teams(orderBy: {field: NAME, direction: ASC}, first: 100, after: $teamsCursor)"`
	} `graphql:"organization(login: $login)"`
}

func QueryGithubOrgRepositoryOwners(ghOrgLogin string, ghClient githubv4.Client) map[string][]string {
	var ownerQuery orgRepositoryOwnerQuery
	log := logger.Get()

	queryVars := map[string]interface{}{
		"login":       githubv4.String(ghOrgLogin),
		"teamsCursor": (*githubv4.String)(nil), // Null after argument to get first page
		"reposCursor": (*githubv4.String)(nil),
	}

	// Gather all teams and all repositories they own, handling pagination for each
	allRepos := map[string][]string{}
	for {
		log.Info().Msg("Querying GitHub API for repository ownership information.")
		err := ghClient.Query(context.Background(), &ownerQuery, queryVars)
		if err != nil {
			log.Panic().Err(err).Msg("Failed to query GitHub!")
		}
		for _, team := range ownerQuery.Organization.Teams.Nodes {
			// TODO: Handle pagination of repositories owned by a team.
			for _, repo := range team.Repositories.Edges {
				switch repo.Permission {
				case "ADMIN", "MAINTAIN":
					_, exists := allRepos[repo.Node.Name]
					if !exists {
						allRepos[repo.Node.Name] = make([]string, 0)
					}
					allRepos[repo.Node.Name] = append(allRepos[repo.Node.Name], team.Slug)
				default:
					continue
				}
			}
		}
		if !ownerQuery.Organization.Teams.PageInfo.HasNextPage {
			break
		}
		queryVars["teamsCursor"] = githubv4.NewString(ownerQuery.Organization.Teams.PageInfo.EndCursor)
	}
	log.Debug().Any("repos", allRepos).Msg("Repositories loaded.")
	return allRepos
}
