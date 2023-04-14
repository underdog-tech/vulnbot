package api

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockSlackClient struct {
	mock.Mock
}

func (m *MockSlackClient) PostMessage(channelID, message string) (string, string, error) {
	args := m.Called(channelID, message)
	return args.String(0), args.String(1), args.Error(2)
}

func TestSendSlackMessages(t *testing.T) {
	// Create a mock Slack client
	mockClient := new(MockSlackClient)

	// Set up test messages
	messages := map[string]string{
		"channel1": "message1",
		"channel2": "message2",
	}

	// Test case 1: Successful send
	mockClient.On("PostMessage", "channel1", "message1").Return("", "", nil).Once()

	// Test case 2: Error sending Slack message
	mockClient.On("PostMessage", "channel2", "message2").Return("", "", fmt.Errorf("Failed to send Slack message")).Once()

	// Run tests
	SendSlackMessages(messages, mockClient)

	mockClient.AssertExpectations(t)
}

func TestPostMessage(t *testing.T) {
	// Create a mock SlackClientInterface
	mockClient := new(MockSlackClient)

	// Set up expected method calls on the mockClient
	mockClient.On("PostMessage", "channelID", "message").Return("response1", "response2", nil).Once()

	// Call the method being tested
	response1, response2, err := mockClient.PostMessage("channelID", "message")

	// Assert the expected results
	assert.Equal(t, "response1", response1)
	assert.Equal(t, "response2", response2)
	assert.NoError(t, err)

	// Assert that the expected method was called on the mockClient
	mockClient.AssertExpectations(t)
}
