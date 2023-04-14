package api

import (
	"fmt"
	"testing"

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

	// Set up expected method calls on the mockClient

	// Test case 1: Successful send
	mockClient.On("PostMessage", "channel1", "message1").Return("", "", nil).Once()

	// Test case 2: Error sending Slack message
	mockClient.On("PostMessage", "channel2", "message2").Return("", "", fmt.Errorf("Failed to send Slack message")).Once()

	// Run tests
	SendSlackMessages(messages, mockClient)

	mockClient.AssertExpectations(t)
}
