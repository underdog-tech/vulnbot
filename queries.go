package main

import (
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

var alertQuery struct {
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
