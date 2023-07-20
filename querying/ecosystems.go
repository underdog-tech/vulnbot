package querying

type FindingEcosystemType uint8

const (
	FindingEcosystemApt FindingEcosystemType = iota
	FindingEcosystemCSharp
	FindingEcosystemDart
	FindingEcosystemErlang
	FindingEcosystemGHA // GitHub Actions
	FindingEcosystemGo
	FindingEcosystemJava
	FindingEcosystemJS
	FindingEcosystemPHP
	FindingEcosystemPython
	FindingEcosystemRPM
	FindingEcosystemRuby
	FindingEcosystemRust
	FindingEcosystemSwift
)
