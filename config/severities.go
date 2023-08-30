package config

type FindingSeverityType uint8

const (
	FindingSeverityCritical FindingSeverityType = iota
	FindingSeverityHigh
	FindingSeverityModerate
	FindingSeverityLow
	FindingSeverityInfo
	FindingSeverityUndefined
)

var SeverityNames = map[FindingSeverityType]string{
	FindingSeverityCritical:  "Critical",
	FindingSeverityHigh:      "High",
	FindingSeverityModerate:  "Moderate",
	FindingSeverityLow:       "Low",
	FindingSeverityInfo:      "Info",
	FindingSeverityUndefined: "Undefined",
}

// NewSeverityMap returns a map of finding severities all associated with a
// value of 0, meant to be populated with a count of findings in the relevant
// scope. Notably, this map does not include either "Info" or "Undefined"
// severities, as these are only reported if present.
func NewSeverityMap() map[FindingSeverityType]int {
	return map[FindingSeverityType]int{
		FindingSeverityCritical: 0,
		FindingSeverityHigh:     0,
		FindingSeverityModerate: 0,
		FindingSeverityLow:      0,
	}
}

// GetSeverityReportOrder returns the order in which we want to report severities.
// This is necessary because we cannot declare a constant array in Go.
func GetSeverityReportOrder() []FindingSeverityType {
	return []FindingSeverityType{
		FindingSeverityCritical,
		FindingSeverityHigh,
		FindingSeverityModerate,
		FindingSeverityLow,
		FindingSeverityInfo,
		FindingSeverityUndefined,
	}
}

func GetConsoleSeverityColors() map[FindingSeverityType]string {
	return map[FindingSeverityType]string{
		FindingSeverityCritical:  "#B21515",
		FindingSeverityHigh:      "#D26C00",
		FindingSeverityModerate:  "#FBD100",
		FindingSeverityLow:       "#233EB5",
		FindingSeverityInfo:      "#56B8F5",
		FindingSeverityUndefined: "#CFD0D1",
	}
}

type SeverityConfig struct {
	Label       string
	Slack_emoji string
}
