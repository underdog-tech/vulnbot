package querying

import "sync"

type FindingIdentifierType string
type FindingIdentifierMap map[FindingIdentifierType]string

const (
	FindingIdentifierCVE  FindingIdentifierType = "CVE"
	FindingIdentifierGHSA FindingIdentifierType = "GHSA"
)

type Finding struct {
	Identifiers FindingIdentifierMap
	Ecosystem   FindingEcosystemType
	Severity    FindingSeverityType
	Description string
	PackageName string
	mu          sync.Mutex
}
