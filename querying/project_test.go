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

func TestGetFindingAddsToProject(t *testing.T) {
	project := querying.NewProject("Improbability Drive")
	assert.Len(t, project.Findings, 0)
	finding := project.GetFinding(
		querying.FindingIdentifierMap{
			querying.FindingIdentifierCVE: "CVE-42",
		},
	)
	assert.Len(t, project.Findings, 1)
	assert.Equal(t, finding, project.Findings[0])
}

func TestFindingsAreNotDuplicated(t *testing.T) {
	project := querying.NewProject("Improbability Drive")
	identifiers := querying.FindingIdentifierMap{
		querying.FindingIdentifierCVE: "CVE-42",
	}
	finding1 := project.GetFinding(identifiers)
	finding2 := project.GetFinding(identifiers)
	assert.Len(t, project.Findings, 1)
	assert.Equal(t, finding1, finding2)
}

func TestFindingIdentifiersAreMerged(t *testing.T) {
	project := querying.NewProject("Improbability Drive")
	id_single := querying.FindingIdentifierMap{
		querying.FindingIdentifierCVE: "CVE-42",
	}
	id_multi := querying.FindingIdentifierMap{
		querying.FindingIdentifierCVE:  "CVE-42",
		querying.FindingIdentifierGHSA: "GHSA-4242",
	}
	finding1 := project.GetFinding(id_single)
	finding2 := project.GetFinding(id_multi)
	assert.Len(t, project.Findings, 1)
	assert.Equal(t, finding1, finding2)
	assert.Equal(t, finding1.Identifiers, id_multi)
	assert.Equal(t, project.Findings[0].Identifiers, id_multi)
}
