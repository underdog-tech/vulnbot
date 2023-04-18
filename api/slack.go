package api

import (
	"vulnbot/logger"

	"github.com/slack-go/slack"
)

type SlackClientInterface interface {
	PostMessage(channelID string, options ...slack.MsgOption) (string, string, error)
}

func NewSlackClient(slackToken string) SlackClientInterface {
	return slack.New(slackToken, slack.OptionDebug(true))
}

func SendSlackMessages(messages map[string]string, client SlackClientInterface) {
	log := logger.Get()
	for channel, message := range messages {
		_, timestamp, err := client.PostMessage(channel, slack.MsgOptionText(message, false), slack.MsgOptionAsUser(true))
		if err != nil {
			log.Error().Err(err).Msg("Failed to send Slack message.")
		} else {
			log.Info().Str("channel", channel).Str("timestamp", timestamp).Msg("Message sent to Slack.")
		}
	}
}
