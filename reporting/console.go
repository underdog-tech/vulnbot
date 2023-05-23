package reporting

import (
	"fmt"
	"sort"
	"sync"

	"github.com/gookit/color"
	"github.com/underdog-tech/vulnbot/config"
	"golang.org/x/exp/maps"
)

// These match the colors of the icons that we are currently using in Slack
func getConsoleSeverityColors() map[string]string {
	return map[string]string{
		"Critical": "#c10003",
		"High":     "#e32a33",
		"Moderate": "#e46919",
		"Low":      "#2a9e30",
	}
}

// This will eventually pull from config instead
func getConsoleEcosystemIcons() map[string]string {
	return map[string]string{
		"Go":       "🦦",
		"Maven":    "🪶 ",
		"Npm":      "⬢ ",
		"Pip":      "🐍",
		"Rubygems": "♦️ ",
	}
}

type ConsoleReporter struct {
	Config config.TomlConfig
}

// SendSummaryReport generates a brief report summarizing all the discovered
// vulnerabilities, and prints them out neatly and concisely to the console.
func (c *ConsoleReporter) SendSummaryReport(
	header string,
	numRepos int,
	report VulnerabilityReport,
	wg *sync.WaitGroup,
) error {
	defer wg.Done()
	summaryReport := color.Bold.Sprint(header) + "\n"
	summaryReport += fmt.Sprintf("Total repositories: %d\n", numRepos)
	summaryReport += fmt.Sprintf("Total vulnerabilities: %d\n", report.TotalCount)
	summaryReport += fmt.Sprintf("Affected repositories: %d\n", report.AffectedRepos)
	summaryReport += color.Bold.Sprint("Breakdown by Severity") + "\n"
	severities := getSeverityReportOrder()
	severityColors := getConsoleSeverityColors()
	for _, severity := range severities {
		title := color.HEX(severityColors[severity]).Sprint(severity)
		summaryReport += fmt.Sprintf("%s: %d\n", title, report.VulnsBySeverity[severity])
	}
	summaryReport += color.Bold.Sprint("Breakdown by Ecosystem") + "\n"
	ecosystems := maps.Keys(report.VulnsByEcosystem)
	sort.Strings(ecosystems)
	ecosystemIcons := getConsoleEcosystemIcons()
	for _, ecosystem := range ecosystems {
		summaryReport += fmt.Sprintf("%s %s: %d\n", ecosystemIcons[ecosystem], ecosystem, report.VulnsByEcosystem[ecosystem])
	}
	fmt.Printf(summaryReport)
	return nil
}

// SendTeamReports is a noop for the Console reporter for the time being.
// Without taking a lot of time to focus on proper formatting, the output
// of this could be quite overwhelming.
func (c *ConsoleReporter) SendTeamReports(
	teamReports map[string]map[string]VulnerabilityReport,
	wg *sync.WaitGroup,
) error {
	defer wg.Done()
	return nil
}
