package main

import (
	"context"
	"fmt"

	"github.com/shurcooL/githubv4"
)

type vulnerabilityAlert struct {
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

type repository struct {
	Name                string
	IsArchived          bool
	VulnerabilityAlerts struct {
		TotalCount int
		Nodes      []vulnerabilityAlert
	} `graphql:"vulnerabilityAlerts(first: 100, states: OPEN)"`
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
			Nodes []repository
		} `graphql:"repositories(orderBy: {field: NAME, direction: ASC}, isFork: false, first: 100, after: $reposCursor)"`
	} `graphql:"organization(login: $login)"`
}

func getGithubOrgVulnerabilities(ghOrgLogin string, ghClient githubv4.Client) (orgName string, repositories []repository) {
	var alertQuery orgVulnerabilityQuery

	// Construct the variables necessary for our GraphQL query
	queryVars := map[string]interface{}{
		"login":       githubv4.String(ghOrgLogin),
		"reposCursor": (*githubv4.String)(nil), // Null after argument to get first page
	}

	// Gather all repositories, handling pagination
	var allRepos []repository
	for {
		fmt.Println("Executing query against GitHub API.")
		err := ghClient.Query(context.Background(), &alertQuery, queryVars)
		if err != nil {
			panic(err)
		}
		allRepos = append(allRepos, alertQuery.Organization.Repositories.Nodes...)
		if !alertQuery.Organization.Repositories.PageInfo.HasNextPage {
			break
		}
		queryVars["reposCursor"] = githubv4.NewString(alertQuery.Organization.Repositories.PageInfo.EndCursor)
	}

	return alertQuery.Organization.Name, allRepos
}
