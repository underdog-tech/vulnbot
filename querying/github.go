package querying

import (
	"context"
	"sync"

	"github.com/shurcooL/githubv4"
	"github.com/underdog-tech/vulnbot/logger"
)

type githubClient interface {
	Query(context.Context, interface{}, map[string]interface{}) error
}

// GithubDataSource is used to pull Dependabot alerts for an individual organization.
type GithubDataSource struct {
	ghClient githubClient
	orgName  string
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
			Nodes struct {
				Name                string
				VulnerabilityAlerts struct {
					TotalCount int
					PageInfo   struct {
						EndCursor   githubv4.String
						HasNextPage bool
					}
					Nodes struct {
						Id               string
						Number           int
						SecurityAdvisory struct {
							Description string
							Identifiers struct {
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
				} `graphql:"vulnerabilityAlerts(states: OPEN, first: 100, after: $alertCursor)"`
			}
		} `graphql:"repositories(orderBy: {field: NAME, direction: ASC}, isFork: false, isArchived: false, first: 100, after: $repoCursor)"`
	} `graphql:"organization(login: $login)"`
}

func (gh *GithubDataSource) CollectFindings(projects *ProjectCollection, wg *sync.WaitGroup) {
	var alertQuery orgVulnerabilityQuery
	log := logger.Get()
	defer wg.Done()

	queryVars := map[string]interface{}{
		"login":       githubv4.String(gh.orgName),
		"repoCursor":  (*githubv4.String)(nil), // We pass nil/null to get the first page
		"alertCursor": (*githubv4.String)(nil),
	}

	for {
		log.Info().Msg("Querying GitHub API for vulnerable repositories.")
		err := gh.ghClient.Query(context.Background(), &alertQuery, queryVars)
		if err != nil {
			log.Error().Err(err).Msg("Failed to query GitHub!")
		}
		// TODO: Process the repositories...
		// I'm thinking a goroutine that takes in projects, repoCursor, and alertCursor
		// then it can handle pagination of the alerts if necessary

		if !alertQuery.Organization.Repositories.PageInfo.HasNextPage {
			break
		}
		queryVars["reposCursor"] = githubv4.NewString(alertQuery.Organization.Repositories.PageInfo.EndCursor)
	}
}
