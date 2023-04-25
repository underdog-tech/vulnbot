package reporting

import (
	"strings"

	"github.com/underdog-tech/vulnbot/api"
	"github.com/underdog-tech/vulnbot/logger"
)

const NO_OWNER_KEY = "__none__"

func TallyVulnsBySeverity(vulns []api.VulnerabilityAlert, vulnCounts map[string]int) {
	for _, vuln := range vulns {
		severity := strings.Title(strings.ToLower(vuln.SecurityVulnerability.Severity))
		vulnCounts[severity] += 1
	}
}

func TallyVulnsByEcosystem(vulns []api.VulnerabilityAlert, vulnCounts map[string]int) {
	for _, vuln := range vulns {
		ecosystem := strings.Title(strings.ToLower(vuln.SecurityVulnerability.Package.Ecosystem))
		_, exists := vulnCounts[ecosystem]
		if !exists {
			vulnCounts[ecosystem] = 0
		}
		vulnCounts[ecosystem] += 1
	}
}

func GetRepositoryOwners(repoName string, repositoryOwners map[string][]string) []string {
	log := logger.Get()
	owners, exists := repositoryOwners[repoName]
	if !exists {
		log.Warn().Str("repo", repoName).Msg("No owners found for repository.")
		return []string{}
	}
	return owners
}

func CollateSummaryReport(repos []api.VulnerabilityRepository) (report VulnerabilityReport) {
	log := logger.Get()
	report = NewVulnerabilityReport()
	for _, repo := range repos {
		repoVulns := repo.VulnerabilityAlerts.TotalCount
		report.TotalCount += repoVulns
		if repoVulns > 0 {
			report.AffectedRepos += 1
		}
		TallyVulnsBySeverity(repo.VulnerabilityAlerts.Nodes, report.VulnsBySeverity)
		TallyVulnsByEcosystem(repo.VulnerabilityAlerts.Nodes, report.VulnsByEcosystem)
	}
	log.Debug().Any("report", report).Msg("Collated summary report.")
	return report
}

func GroupVulnsByOwner(repos []api.VulnerabilityRepository, owners map[string][]string) map[string][]api.VulnerabilityRepository {
	vulnsByTeam := map[string][]api.VulnerabilityRepository{}
	// First, group up the repositories by owner
	for _, repo := range repos {
		owners := GetRepositoryOwners(repo.Name, owners)
		if len(owners) == 0 {
			owners = []string{NO_OWNER_KEY}
		}
		for _, slug := range owners {
			_, exists := vulnsByTeam[slug]
			if !exists {
				vulnsByTeam[slug] = make([]api.VulnerabilityRepository, 0)
			}
			vulnsByTeam[slug] = append(vulnsByTeam[slug], repo)
		}
	}
	return vulnsByTeam
}

func CollateTeamReports(vulnsByTeam map[string][]api.VulnerabilityRepository) (teamReports map[string]map[string]VulnerabilityReport) {
	log := logger.Get()

	teamReports = map[string]map[string]VulnerabilityReport{}
	for team, repos := range vulnsByTeam {
		_, exists := teamReports[team]
		if !exists {
			teamReports[team] = map[string]VulnerabilityReport{}
		}
		teamReports[team][SUMMARY_KEY] = NewVulnerabilityReport()
		for _, repo := range repos {
			summaryReport, _ := teamReports[team][SUMMARY_KEY]
			summaryReport.AffectedRepos += 1
			repoReport := NewVulnerabilityReport()
			TallyVulnsByEcosystem(repo.VulnerabilityAlerts.Nodes, repoReport.VulnsByEcosystem)
			TallyVulnsByEcosystem(repo.VulnerabilityAlerts.Nodes, summaryReport.VulnsByEcosystem)
			TallyVulnsBySeverity(repo.VulnerabilityAlerts.Nodes, repoReport.VulnsBySeverity)
			for severity, count := range repoReport.VulnsBySeverity {
				summaryReport.VulnsBySeverity[severity] += count
				summaryReport.TotalCount += count
				repoReport.TotalCount += count
			}
			teamReports[team][SUMMARY_KEY] = summaryReport
			teamReports[team][repo.Name] = repoReport
		}
		log.Debug().Str("team", team).Any("teamReport", teamReports[team]).Msg("Completed team report.")
	}
	return teamReports
}
