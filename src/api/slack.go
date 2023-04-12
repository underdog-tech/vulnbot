package api

import (
	"vulnbot/src/logger"

	"github.com/slack-go/slack"
)

func SendSlackMessages(slackToken string, messages map[string]string) {
	log := logger.Get()

	if len(slackToken) > 0 {
		slackClient := slack.New(slackToken, slack.OptionDebug(true))
		for channel, message := range messages {
			_, timestamp, err := slackClient.PostMessage(
				channel,
				slack.MsgOptionText(message, false),
				slack.MsgOptionAsUser(true),
			)

			if err != nil {
				log.Error().Err(err).Msg("Failed to send Slack message.")
			}
			log.Info().Str("channel", channel).Str("timestamp", timestamp).Msg("Message sent to Slack.")
		}
	} else {
		log.Warn().Msg("No Slack token found. Skipping communication.")
	}
}
