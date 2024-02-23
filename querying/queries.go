package querying

import "github.com/shurcooL/githubv4"

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

type repositoryTopics struct {
	Edges []struct {
		Node struct {
			Topic struct {
				Name string
			}
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
				Name             string
				IsFork           bool
				IsArchived       bool
				RepositoryTopics repositoryTopics `graphql:"repositoryTopics(first: 10, last: null)"`
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
