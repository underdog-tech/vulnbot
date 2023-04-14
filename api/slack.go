package api

import (
	"vulnbot/logger"

	"github.com/slack-go/slack"
)

type SlackClientInterface interface {
	PostMessage(channelID, message string) (string, string, error)
}

type SlackClient struct {
	client slack.Client
}

func (s *SlackClient) PostMessage(channelID string, message string) (string, string, error) {
	return s.client.PostMessage(channelID, slack.MsgOptionText(message, false), slack.MsgOptionAsUser(true))
}

func NewSlackClient(slackToken string) SlackClientInterface {
	return &SlackClient{
		client: *slack.New(slackToken, slack.OptionDebug(true)),
	}
}

func SendSlackMessages(messages map[string]string, client SlackClientInterface) {
	log := logger.Get()
	for channel, message := range messages {
		_, timestamp, err := client.PostMessage(channel, message)
		if err != nil {
			log.Error().Err(err).Msg("Failed to send Slack message.")
		}
		log.Info().Str("channel", channel).Str("timestamp", timestamp).Msg("Message sent to Slack.")
	}
}
