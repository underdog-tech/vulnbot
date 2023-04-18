package api

import (
	"fmt"
	"testing"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockSlackClient struct {
	mock.Mock
}

func (m *MockSlackClient) PostMessage(channelID string, options ...slack.MsgOption) (string, string, error) {
	args := m.Called(channelID, options)
	return args.String(0), args.String(1), args.Error(2)
}

func TestSendSlackMessagesSuccess(t *testing.T) {
	// Create a mock Slack client
	mockClient := new(MockSlackClient)

	// Set up test messages
	messages := map[string]string{
		"channel": "message",
	}

	// Test case: Successful send
	mockClient.On("PostMessage", "channel", mock.Anything, mock.Anything).Return("", "", nil).Once()

	// Run tests
	SendSlackMessages(messages, mockClient)

	mockClient.AssertExpectations(t)
}

func TestSendSlackMessagesError(t *testing.T) {
	// Create a mock Slack client
	mockClient := new(MockSlackClient)

	// Set up test messages
	messages := map[string]string{
		"channel": "message",
	}

	// Test case: Error sending Slack message
	mockClient.On("PostMessage", "channel", mock.Anything, mock.Anything).Return("", "", fmt.Errorf("Failed to send Slack message")).Once()

	// Run tests
	SendSlackMessages(messages, mockClient)

	mockClient.AssertExpectations(t)
}

func TestPostMessage(t *testing.T) {
	// Create a mock SlackClientInterface
	mockClient := new(MockSlackClient)

	slackClient := &SlackClient{
		client: mockClient,
	}

	// Set up expected method calls on the mockClient
	mockClient.On("PostMessage", "channelID", mock.Anything, mock.Anything).Return("response1", "response2", nil).Once()

	// Call the method being tested
	response1, response2, err := slackClient.PostMessage("channelID", slack.MsgOptionText(mock.Anything, false), slack.MsgOptionAsUser(true))

	// Assert the expected results
	assert.Equal(t, "response1", response1)
	assert.Equal(t, "response2", response2)
	assert.NoError(t, err)

	// Assert that the expected method was called on the mockClient
	mockClient.AssertExpectations(t)
}

func TestNewSlackClient(t *testing.T) {
	// Call the NewSlackClient function with the mockClient
	slackClient := NewSlackClient("slackToken")

	// Assert the expected behavior
	assert.NotNil(t, slackClient)
}
