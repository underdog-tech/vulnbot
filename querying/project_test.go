package querying_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/underdog-tech/vulnbot/querying"
)

func TestGetProjectAddsToCollection(t *testing.T) {
	projects := querying.NewProjectCollection()
	assert.Len(t, projects.Projects, 0)
	proj := projects.GetProject("Improbability Drive")
	assert.Len(t, projects.Projects, 1)
	assert.Equal(t, proj, projects.Projects[0])
}

func TestProjectNameIsNormalized(t *testing.T) {
	projects := querying.NewProjectCollection()
	proj := projects.GetProject("Heart-of-Gold: Improbability Drive!")
	assert.Equal(t, "heart_of_gold_improbability_drive", proj.Name)
}

func TestProjectsAreNotDuplicated(t *testing.T) {
	projects := querying.NewProjectCollection()
	proj1 := projects.GetProject("Improbability Drive")
	proj2 := projects.GetProject("Improbability Drive")
	assert.Len(t, projects.Projects, 1)
	assert.Equal(t, proj1, proj2)
}
