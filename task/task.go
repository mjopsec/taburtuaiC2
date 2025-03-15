package task

import "sync"

var (
	taskQueue = make(map[string][]string)
	mu        sync.Mutex
)

// AddTask queues a command for a specific agent
func AddTask(agentID string, cmd string) {
	mu.Lock()
	defer mu.Unlock()
	taskQueue[agentID] = append(taskQueue[agentID], cmd)
}

// GetTask retrieves and removes the next command for an agent
func GetTask(agentID string) string {
	mu.Lock()
	defer mu.Unlock()

	if len(taskQueue[agentID]) == 0 {
		return ""
	}

	cmd := taskQueue[agentID][0]
	taskQueue[agentID] = taskQueue[agentID][1:]
	return cmd
}

// HasTask checks if an agent has pending tasks
func HasTask(agentID string) bool {
	mu.Lock()
	defer mu.Unlock()
	return len(taskQueue[agentID]) > 0
}
