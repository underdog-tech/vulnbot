package querying

import (
	"regexp"
	"strings"
	"sync"

	"golang.org/x/exp/maps"
)

type ProjectCollection struct {
	Projects []*Project
	mu       sync.Mutex
}

type Project struct {
	Name     string
	Findings []*Finding
	Links    map[string]string
	mu       sync.Mutex
}

// NewProject returns a new, empty project with no links or findings.
func NewProject(name string) *Project {
	return &Project{
		Name:     name,
		Findings: []*Finding{},
		Links:    map[string]string{},
	}
}

// NewProjectCollection returns a new, empty ProjectCollection object.
func NewProjectCollection() *ProjectCollection {
	return &ProjectCollection{
		Projects: []*Project{},
	}
}

// normalizeProjectName converts a project name to a standard normalized baseline.
// This means stripping out all characters which are not: Letters, numbers,
// spaces, hyphens, or underscores. This is done via a regex, which includes the
// unicode character classes (\p) of `{L}` to represent all letters, and `{N}`
// to represent all numbers.
// Once all undesirable characters have been stripped, both spaces and hyphens
// are converted to underscores, and the resulting string is lower-cased.
func normalizeProjectName(name string) string {
	unacceptableChars := regexp.MustCompile(`[^\p{L}\p{N} \-\_]+`)
	replacer := strings.NewReplacer(
		" ", "_",
		"-", "_",
	)
	return replacer.Replace(
		unacceptableChars.ReplaceAllString(
			strings.ToLower(name), "",
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
