package querying

import "sync"

type FindingIdentifierType uint8

const (
	FindingIdentifierCVE FindingIdentifierType = iota
	FindingIdentifierGHSA
)

type Finding struct {
	Identifiers map[FindingIdentifierType]string
	Ecosystem   FindingEcosystemType
	Severity    FindingSeverityType
	Description string
	PackageName string
	mu          sync.Mutex
}
