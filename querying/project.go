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

func NewProject(name string) *Project {
	return &Project{
		Name:     name,
		Findings: []*Finding{},
		Links:    map[string]string{},
	}
}

func NewProjectCollection() *ProjectCollection {
	return &ProjectCollection{
		Projects: []*Project{},
	}
}

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

func (c *ProjectCollection) AddProject(name string) *Project {
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

func (p *Project) AddFinding(identifiers map[FindingIdentifierType]string) *Finding {
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
	} else {
		maps.Copy(result.Identifiers, identifiers)
	}
	return result
}
