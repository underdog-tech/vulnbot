package querying

import "strings"

const DisableVulnBotTopicKeyword = "disable-vulnbot"

func shouldIgnoreRepository(isArchived bool, isFork bool, topics []string) bool {
	if isArchived || isFork {
		return true
	}
	for _, topic := range topics {
		if strings.Contains(strings.ToLower(topic), DisableVulnBotTopicKeyword) {
			return true
		}
	}
	return false
}
