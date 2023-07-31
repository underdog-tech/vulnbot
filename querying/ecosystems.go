package querying

type FindingEcosystemType string

const (
	FindingEcosystemApt    FindingEcosystemType = "apt"
	FindingEcosystemCSharp                      = "csharp"
	FindingEcosystemDart                        = "dart"
	FindingEcosystemErlang                      = "erlang"
	FindingEcosystemGHA                         = "gha" // GitHub Actions
	FindingEcosystemGo                          = "go"
	FindingEcosystemJava                        = "java"
	FindingEcosystemJS                          = "js" // Includes TypeScript
	FindingEcosystemPHP                         = "php"
	FindingEcosystemPython                      = "python"
	FindingEcosystemRPM                         = "rpm"
	FindingEcosystemRuby                        = "ruby"
	FindingEcosystemRust                        = "rust"
	FindingEcosystemSwift                       = "swift"
)
