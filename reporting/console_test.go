package reporting

import (
	"fmt"
	"io/ioutil"
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
	report := NewVulnerabilityReport()
	report.AffectedRepos = 2
	report.TotalCount = 42
	report.VulnsByEcosystem["Pip"] = 2
	report.VulnsByEcosystem["Npm"] = 40
	report.VulnsBySeverity["Critical"] = 10
	report.VulnsBySeverity["High"] = 10
	report.VulnsBySeverity["Moderate"] = 10
	report.VulnsBySeverity["Low"] = 12
	severityColors := getConsoleSeverityColors()
	ecosystemIcons := getConsoleEcosystemIcons()
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
%s Npm: 40
%s Pip: 2
`,
		color.Bold.Sprint("OrgName Dependabot Report"),
		color.Style{color.OpItalic}.Sprint(TEST_REPORT_TIME_FORMATTED),
		color.Bold.Sprint("Breakdown by Severity"),
		color.HEX(severityColors["Critical"]).Sprint("Critical"),
		color.HEX(severityColors["High"]).Sprint("High"),
		color.HEX(severityColors["Moderate"]).Sprint("Moderate"),
		color.HEX(severityColors["Low"]).Sprint("Low"),
		color.Bold.Sprint("Breakdown by Ecosystem"),
		ecosystemIcons["Npm"],
		ecosystemIcons["Pip"],
	)

	wg := new(sync.WaitGroup)
	wg.Add(1)
	reporter.SendSummaryReport("OrgName Dependabot Report", 13, report, TEST_REPORT_TIME, wg)
	writer.Close()
	written, _ := ioutil.ReadAll(reader)
	os.Stdout = origStdout
	assert.Equal(t, expected, string(written))
}
