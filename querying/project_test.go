package querying_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/underdog-tech/vulnbot/querying"
)

func TestAddProjectAddsToCollection(t *testing.T) {
	projects := querying.NewProjectCollection()
	assert.Len(t, projects.Projects, 0)
	proj := projects.AddProject("Improbability Drive")
	assert.Len(t, projects.Projects, 1)
	assert.Equal(t, proj, projects.Projects[0])
}

func TestProjectNameIsNormalized(t *testing.T) {
	projects := querying.NewProjectCollection()
	proj := projects.AddProject("Heart-of-Gold: Improbability Drive!")
	assert.Equal(t, "heart_of_gold_improbability_drive", proj.Name)
}

func TestProjectsAreNotDuplicated(t *testing.T) {
	projects := querying.NewProjectCollection()
	proj1 := projects.AddProject("Improbability Drive")
	proj2 := projects.AddProject("Improbability Drive")
	assert.Len(t, projects.Projects, 1)
	assert.Equal(t, proj1, proj2)
}
