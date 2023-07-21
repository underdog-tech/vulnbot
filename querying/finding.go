package querying

import "sync"

type FindingIdentifierType uint8
type FindingIdentifierMap map[FindingIdentifierType]string

const (
	FindingIdentifierCVE FindingIdentifierType = iota
	FindingIdentifierGHSA
)

type Finding struct {
	Identifiers FindingIdentifierMap
	Ecosystem   FindingEcosystemType
	Severity    FindingSeverityType
	Description string
	PackageName string
	mu          sync.Mutex
}
