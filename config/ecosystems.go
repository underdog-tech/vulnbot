package config

type FindingEcosystemType string

const (
	FindingEcosystemApt    FindingEcosystemType = "apt"
	FindingEcosystemCSharp FindingEcosystemType = "csharp"
	FindingEcosystemDart   FindingEcosystemType = "dart"
	FindingEcosystemErlang FindingEcosystemType = "erlang"
	FindingEcosystemGHA    FindingEcosystemType = "gha" // GitHub Actions
	FindingEcosystemGo     FindingEcosystemType = "go"
	FindingEcosystemJava   FindingEcosystemType = "java"
	FindingEcosystemJS     FindingEcosystemType = "js" // Includes TypeScript
	FindingEcosystemPHP    FindingEcosystemType = "php"
	FindingEcosystemPython FindingEcosystemType = "python"
	FindingEcosystemRPM    FindingEcosystemType = "rpm"
	FindingEcosystemRuby   FindingEcosystemType = "ruby"
	FindingEcosystemRust   FindingEcosystemType = "rust"
	FindingEcosystemSwift  FindingEcosystemType = "swift"
)
