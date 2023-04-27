package reporting

const DEFAULT_SLACK_ICON = " "
const NO_OWNER_KEY = "__none__"
const SUMMARY_KEY = "summary"

// Return the order that we want to report severities in.
// This is necessary because we cannot declare a constant array in Go.
func getSeverityReportOrder() []string {
	return []string{"Critical", "High", "Moderate", "Low"}
}

// Return the order that we want to report ecosystems in.
// This is necessary because we cannot declare a constant array in Go.
func getEcosystemReportOrder() []string {
	return []string{"Go", "Npm", "Pip", "Rubygems"}
}
