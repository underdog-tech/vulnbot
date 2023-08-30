package querying

import (
	"sync"

	"github.com/underdog-tech/vulnbot/config"
)

type FindingIdentifierType string
type FindingIdentifierMap map[FindingIdentifierType]string

const (
	FindingIdentifierCVE  FindingIdentifierType = "CVE"
	FindingIdentifierGHSA FindingIdentifierType = "GHSA"
)

type Finding struct {
	Identifiers FindingIdentifierMap
	Ecosystem   config.FindingEcosystemType
	Severity    config.FindingSeverityType
	Description string
	PackageName string
	mu          sync.Mutex
}
