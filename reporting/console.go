package reporting

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/gookit/color"
	"golang.org/x/exp/maps"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/underdog-tech/vulnbot/configs"
)

type ConsoleReporter struct {
	Config *configs.Config
}

// SendSummaryReport generates a brief report summarizing all the discovered
// vulnerabilities, and prints them out neatly and concisely to the console.
func (c *ConsoleReporter) SendSummaryReport(
	header string,
	numRepos int,
	report FindingSummary,
	reportTime time.Time,
	teamSummaries TeamSummaries,
	wg *sync.WaitGroup,
) error {
	defer wg.Done()
	summaryReport := color.Bold.Sprint(header) + "\n"
	summaryReport += color.Style{color.OpItalic}.Sprint(reportTime.Format(DATE_LAYOUT)) + "\n\n"
	summaryReport += fmt.Sprintf("Total repositories: %d\n", numRepos)
	summaryReport += fmt.Sprintf("Total vulnerabilities: %d\n", report.TotalCount)
	summaryReport += fmt.Sprintf("Affected repositories: %d\n", report.AffectedRepos)
	summaryReport += "\n" + color.Bold.Sprint("Breakdown by Severity") + "\n"
	severities := GetSeverityReportOrder()
	severityColors := configs.GetConsoleSeverityColors()
	for _, severity := range severities {
		sevCount, exists := report.VulnsBySeverity[severity]
		if exists {
			title := color.HEX(severityColors[severity]).Sprint(configs.SeverityNames[severity])
			summaryReport += fmt.Sprintf("%s: %d\n", title, sevCount)
		}
	}
	summaryReport += "\n" + color.Bold.Sprint("Breakdown by Ecosystem") + "\n"
	ecosystems := maps.Keys(report.VulnsByEcosystem)
	ecosystemIcons := configs.GetConsoleEcosystemIcons()

	caser := cases.Title(language.English)
	sort.Slice(ecosystems, func(i, j int) bool { return ecosystems[i] < ecosystems[j] })
	for _, ecosystem := range ecosystems {
		summaryReport += fmt.Sprintf("%s %s: %d\n", ecosystemIcons[ecosystem], caser.String(string(ecosystem)), report.VulnsByEcosystem[ecosystem])
	}
	fmt.Print(summaryReport)
	return nil
}

// SendTeamReports is a noop for the Console reporter for the time being.
// Without taking a lot of time to focus on proper formatting, the output
// of this could be quite overwhelming.
func (c *ConsoleReporter) SendTeamReports(
	teamReports map[configs.TeamConfig]TeamProjectCollection,
	reportTime time.Time,
	wg *sync.WaitGroup,
) error {
	defer wg.Done()
	return nil
}
