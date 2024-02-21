package querying

import (
	"sync"

	"github.com/underdog-tech/vulnbot/configs"
)

type FindingIdentifierType string
type FindingIdentifierMap map[FindingIdentifierType]string

const (
	FindingIdentifierCVE  FindingIdentifierType = "CVE"
	FindingIdentifierGHSA FindingIdentifierType = "GHSA"
)

// A Finding represents a single finding / vulnerability in a project. For
// example, a CVE. A [Project] must never have duplicates of the same Finding.
type Finding struct {
	Identifiers FindingIdentifierMap
	Ecosystem   configs.FindingEcosystemType
	Severity    configs.FindingSeverityType
	Description string
	PackageName string
	mu          sync.Mutex
}
