package reporting

import (
	"fmt"
	"io"
	"os"
	"sync"
	"testing"

	"github.com/gookit/color"
	"github.com/stretchr/testify/assert"
	"github.com/underdog-tech/vulnbot/config"
)

func TestSendConsoleSummaryReport(t *testing.T) {
	origStdout := os.Stdout
	reader, writer, _ := os.Pipe()
	os.Stdout = writer

	reporter := ConsoleReporter{Config: config.Config{}}
	report := NewFindingSummary()
	report.AffectedRepos = 2
	report.TotalCount = 42
	report.VulnsByEcosystem[config.FindingEcosystemPython] = 2
	report.VulnsByEcosystem[config.FindingEcosystemJS] = 40
	report.VulnsBySeverity[config.FindingSeverityCritical] = 10
	report.VulnsBySeverity[config.FindingSeverityHigh] = 10
	report.VulnsBySeverity[config.FindingSeverityModerate] = 10
	report.VulnsBySeverity[config.FindingSeverityLow] = 12
	severityColors := config.GetConsoleSeverityColors()
	ecosystemIcons := config.GetConsoleEcosystemIcons()
	expected := fmt.Sprintf(`%s
%s

Total repositories: 13
Total vulnerabilities: 42
Affected repositories: 2

%s
%s: 10
%s: 10
%s: 10
%s: 12

%s
%s Js: 40
%s Python: 2
`,
		color.Bold.Sprint("OrgName Dependabot Report"),
		color.Style{color.OpItalic}.Sprint(TEST_REPORT_TIME_FORMATTED),
		color.Bold.Sprint("Breakdown by Severity"),
		color.HEX(severityColors[config.FindingSeverityCritical]).Sprint("Critical"),
		color.HEX(severityColors[config.FindingSeverityHigh]).Sprint("High"),
		color.HEX(severityColors[config.FindingSeverityModerate]).Sprint("Moderate"),
		color.HEX(severityColors[config.FindingSeverityLow]).Sprint("Low"),
		color.Bold.Sprint("Breakdown by Ecosystem"),
		ecosystemIcons[config.FindingEcosystemJS],
		ecosystemIcons[config.FindingEcosystemPython],
	)

	wg := new(sync.WaitGroup)
	wg.Add(1)
	_ = reporter.SendSummaryReport("OrgName Dependabot Report", 13, report, TEST_REPORT_TIME, wg)
	writer.Close()
	written, _ := io.ReadAll(reader)
	os.Stdout = origStdout
	assert.Equal(t, expected, string(written))
}
