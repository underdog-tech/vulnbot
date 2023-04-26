package reporting

import (
	"fmt"
	"sync"
	"testing"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/underdog-tech/vulnbot/config"
)

type MockSlackClient struct {
	mock.Mock
}

func (m *MockSlackClient) PostMessage(channelID string, options ...slack.MsgOption) (string, string, error) {
	args := m.Called(channelID, options)
	return args.String(0), args.String(1), args.Error(2)
}

func TestSendSlackMessagesSuccess(t *testing.T) {
	mockClient := new(MockSlackClient)
	config := config.TomlConfig{}
	reporter := SlackReporter{config: config, client: mockClient}

	mockClient.On("PostMessage", "channel", mock.Anything, mock.Anything).Return("", "", nil).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	reporter.sendSlackMessage("channel", "message", wg)

	mockClient.AssertExpectations(t)
}

func TestSendSlackMessagesError(t *testing.T) {
	mockClient := new(MockSlackClient)
	config := config.TomlConfig{}
	reporter := SlackReporter{config: config, client: mockClient}

	mockClient.On("PostMessage", "channel", mock.Anything, mock.Anything).Return("", "", fmt.Errorf("Failed to send Slack message")).Once()

	wg := new(sync.WaitGroup)
	wg.Add(1)
	reporter.sendSlackMessage("channel", "message", wg)

	mockClient.AssertExpectations(t)
}

func TestIsSlackTokenMissing(t *testing.T) {
	_, err := NewSlackReporter(config.TomlConfig{}, "")
	assert.Error(t, err)
}

func TestSlackTokenIsNotMissing(t *testing.T) {
	_, err := NewSlackReporter(config.TomlConfig{}, "slackToken")
	assert.NoError(t, err)
}
