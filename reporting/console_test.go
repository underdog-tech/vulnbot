package reporting_test

import (
	"fmt"
	"io"
	"os"
	"sync"
	"testing"

	"github.com/gookit/color"
	"github.com/stretchr/testify/assert"
	"github.com/underdog-tech/vulnbot/configs"
	"github.com/underdog-tech/vulnbot/reporting"
	"github.com/underdog-tech/vulnbot/test"
)

func TestSendConsoleSummaryReport(t *testing.T) {
	origStdout := os.Stdout
	reader, writer, _ := os.Pipe()
	os.Stdout = writer

	reporter := reporting.ConsoleReporter{Config: &configs.Config{}}
	report := reporting.NewFindingSummary()
	report.AffectedRepos = 2
	report.TotalCount = 42
	report.VulnsByEcosystem[configs.FindingEcosystemPython] = 2
	report.VulnsByEcosystem[configs.FindingEcosystemJS] = 40
	report.VulnsBySeverity[configs.FindingSeverityCritical] = 10
	report.VulnsBySeverity[configs.FindingSeverityHigh] = 10
	report.VulnsBySeverity[configs.FindingSeverityModerate] = 10
	report.VulnsBySeverity[configs.FindingSeverityLow] = 12
	severityColors := configs.GetConsoleSeverityColors()
	ecosystemIcons := configs.GetConsoleEcosystemIcons()
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
		color.Style{color.OpItalic}.Sprint(test.TEST_REPORT_TIME_FORMATTED),
		color.Bold.Sprint("Breakdown by Severity"),
		color.HEX(severityColors[configs.FindingSeverityCritical]).Sprint("Critical"),
		color.HEX(severityColors[configs.FindingSeverityHigh]).Sprint("High"),
		color.HEX(severityColors[configs.FindingSeverityModerate]).Sprint("Moderate"),
		color.HEX(severityColors[configs.FindingSeverityLow]).Sprint("Low"),
		color.Bold.Sprint("Breakdown by Ecosystem"),
		ecosystemIcons[configs.FindingEcosystemJS],
		ecosystemIcons[configs.FindingEcosystemPython],
	)

	wg := new(sync.WaitGroup)
	wg.Add(1)
	_ = reporter.SendSummaryReport("OrgName Dependabot Report", 13, report, test.TEST_REPORT_TIME, test.TEST_TEAM_SUMMARIES, wg)
	writer.Close()
	written, _ := io.ReadAll(reader)
	os.Stdout = origStdout
	assert.Equal(t, expected, string(written))
}
