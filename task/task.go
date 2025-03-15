package task

import (
	"sync"
	"time"
)

var (
	taskQueue = make(map[string][]string)
	mu        sync.Mutex

	scheduledTasks []ScheduledTask
)

// ScheduledTask menyimpan jadwal command untuk eksekusi di masa depan
type ScheduledTask struct {
	AgentID      string
	Command      string
	ScheduleTime time.Time
	Executed     bool
}

// AddTask queues a command for a specific agent (eksekusi segera)
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

// -------------------- Scheduled Task Logic --------------------

// AddScheduledTask menambahkan jadwal command di masa depan
func AddScheduledTask(agentID, cmd string, schedule time.Time) {
	mu.Lock()
	defer mu.Unlock()

	scheduledTasks = append(scheduledTasks, ScheduledTask{
		AgentID:      agentID,
		Command:      cmd,
		ScheduleTime: schedule,
		Executed:     false,
	})
}

// CheckScheduledTasks dijalankan di goroutine terpisah, cek tiap detik
func CheckScheduledTasks() {
	for {
		time.Sleep(1 * time.Second)
		now := time.Now()

		mu.Lock()
		for i, st := range scheduledTasks {
			if !st.Executed && now.After(st.ScheduleTime) {
				// Waktunya eksekusi
				taskQueue[st.AgentID] = append(taskQueue[st.AgentID], st.Command)
				scheduledTasks[i].Executed = true
				// boleh log, misalnya: fmt.Printf("[*] Scheduled command triggered for agent %s\n", st.AgentID)
			}
		}
		mu.Unlock()
	}
}
