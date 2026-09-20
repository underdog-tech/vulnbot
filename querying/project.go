package querying

import (
	"regexp"
	"strings"
	"sync"

	mapset "github.com/deckarep/golang-set/v2"
	"golang.org/x/exp/maps"

	"github.com/underdog-tech/vulnbot/configs"
)

type ProjectCollection struct {
	Projects []*Project
	mu       sync.Mutex
}

// A Project represents a single project which contains findings.
//
// Examples of a Project would be a GitHub repository, or an Amazon ECR image.
//
// Links represents where the Project can be found. For example, if a Project
// exists in a GitHub repository, then it would contain a Links entry with a
// key of "GitHub" and value of "https://github.com/org-name/project-name".
// These links are meant to be displayed out by reporters, to give users quick
// access to the projects and their findings.
type Project struct {
	Name     string
	Findings []*Finding
	Link     string
	Owners   mapset.Set[configs.TeamConfig]
	// IsFork is only ever true for a Project that came through
	// GithubDataSource.ForkProjects (see querying/github.go) - the main
	// vulnerability-scanning query already excludes forks entirely, so any
	// Project reaching the main ProjectCollection via that path is
	// guaranteed non-fork.
	IsFork bool
	// Visibility is GitHub's repository visibility as returned by its
	// GraphQL API's `visibility` field: "PUBLIC", "PRIVATE", or
	// "INTERNAL" (GitHub Enterprise only). Deliberately not the older
	// `isPrivate` boolean, which returns true for Internal repos too and
	// so can't distinguish the two - verified against real reports of
	// that ambiguity before choosing this field. Left as GitHub's raw
	// value here; reporters are responsible for their own display
	// formatting (see reporting.notionVisibilityLabel).
	Visibility string
	mu         sync.Mutex
}

// NewProject returns a new, empty project with no links or findings.
func NewProject(name string) *Project {
	return &Project{
		Name:     name,
		Findings: []*Finding{},
		Owners:   mapset.NewSet[configs.TeamConfig](),
	}
}

// NewProjectCollection returns a new, empty ProjectCollection object.
func NewProjectCollection() *ProjectCollection {
	return &ProjectCollection{
		Projects: []*Project{},
	}
}

// normalizeProjectName converts a project name to a standard normalized format.
// This means stripping out all characters which are not: Letters, numbers,
// spaces, hyphens, or underscores. This is done via a regex, which includes the
// unicode character classes (\p) of `{L}` to represent all letters, and `{N}`
// to represent all numbers.
// Once all undesirable characters have been stripped, both spaces and hyphens
// are converted to underscores, and the resulting string is lower-cased.
//
// For example:
//
//	$$$ This Project is MONEY! $$$
//
// will be normalized to
//
//	this_project_is_money
func normalizeProjectName(name string) string {
	unacceptableChars := regexp.MustCompile(`[^\p{L}\p{N} \-\_]+`)
	replacer := strings.NewReplacer(
		" ", "_",
		"-", "_",
	)
	return replacer.Replace(
		strings.TrimSpace(
			unacceptableChars.ReplaceAllString(
				strings.ToLower(name), "",
			),
		),
	)
}

// GetProject returns the project with the specified name from the collection.
// If such a project does not yet exist, it is created and added to the collection.
func (c *ProjectCollection) GetProject(name string) *Project {
	c.mu.Lock()
	defer c.mu.Unlock()
	name = normalizeProjectName(name)
	for _, proj := range c.Projects {
		if normalizeProjectName(proj.Name) == name {
			return proj
		}
	}
	// If we make it past the loop, no existing project was found with this name
	newProj := NewProject(name)
	c.Projects = append(c.Projects, newProj)
	return newProj
}

// GetFinding returns the specified finding from the project, based on the identifiers.
// If such a finding does not yet exist, it is created and added to the project.
func (p *Project) GetFinding(identifiers FindingIdentifierMap) *Finding {
	var result *Finding
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, finding := range p.Findings {
		for idType, id := range finding.Identifiers {
			val, ok := identifiers[idType]
			if ok && val == id {
				result = finding
				break
			}
		}
	}
	if result == nil {
		result = &Finding{
			Identifiers: identifiers,
		}
		p.Findings = append(p.Findings, result)
	} else {
		result.mu.Lock()
		defer result.mu.Unlock()
		maps.Copy(result.Identifiers, identifiers)
	}
	return result
}