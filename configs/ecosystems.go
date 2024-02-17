package configs

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

func GetConsoleEcosystemIcons() map[FindingEcosystemType]string {
	return map[FindingEcosystemType]string{
		FindingEcosystemGo:     "🦦",
		FindingEcosystemJava:   "🪶 ",
		FindingEcosystemJS:     "⬢ ",
		FindingEcosystemPython: "🐍",
		FindingEcosystemRuby:   "♦️ ",
	}
}

type EcosystemConfig struct {
	Label       string
	Slack_emoji string
}
