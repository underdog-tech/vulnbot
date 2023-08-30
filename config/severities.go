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
