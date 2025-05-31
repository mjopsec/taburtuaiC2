// server/services/group_manager.go
package services

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/mjopsec/taburtuaiC2/shared/types"
)

// GroupManager handles agent grouping and mass operations
type GroupManager struct {
	groups   map[string]*AgentGroup
	agentMap map[string]string // agentID -> groupID
	mutex    sync.RWMutex
}

type AgentGroup struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	AgentIDs    []string               `json:"agent_ids"`
	Tags        []string               `json:"tags"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type BulkCommandRequest struct {
	GroupID       string   `json:"group_id"`
	AgentIDs      []string `json:"agent_ids,omitempty"`
	Command       string   `json:"command"`
	Timeout       int      `json:"timeout"`
	MaxConcurrent int      `json:"max_concurrent"`
}

type BulkCommandResult struct {
	TaskID    string                    `json:"task_id"`
	Status    string                    `json:"status"`
	Total     int                       `json:"total"`
	Completed int                       `json:"completed"`
	Failed    int                       `json:"failed"`
	Results   map[string]*types.Command `json:"results"`
}

// CommandQueueInterface defines the interface for command queue operations
// This allows us to avoid circular imports while still having access to queue functionality
type CommandQueueInterface interface {
	Add(agentID string, cmd *types.Command) error
	GetCommand(commandID string) *types.Command
	GetStats() map[string]interface{}
}

func NewGroupManager() *GroupManager {
	return &GroupManager{
		groups:   make(map[string]*AgentGroup),
		agentMap: make(map[string]string),
	}
}

// CreateGroup creates a new agent group
func (gm *GroupManager) CreateGroup(name, description string, tags []string) *AgentGroup {
	gm.mutex.Lock()
	defer gm.mutex.Unlock()

	group := &AgentGroup{
		ID:          generateUUID(),
		Name:        name,
		Description: description,
		AgentIDs:    make([]string, 0),
		Tags:        tags,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Metadata:    make(map[string]interface{}),
	}

	gm.groups[group.ID] = group
	return group
}

// AddAgentToGroup adds an agent to a group
func (gm *GroupManager) AddAgentToGroup(groupID, agentID string) error {
	gm.mutex.Lock()
	defer gm.mutex.Unlock()

	group, exists := gm.groups[groupID]
	if !exists {
		return fmt.Errorf("group not found")
	}

	// Remove from current group if exists
	if currentGroup, exists := gm.agentMap[agentID]; exists {
		gm.removeAgentFromGroupUnsafe(currentGroup, agentID)
	}

	// Add to new group
	group.AgentIDs = append(group.AgentIDs, agentID)
	group.UpdatedAt = time.Now()
	gm.agentMap[agentID] = groupID

	return nil
}

// RemoveAgentFromGroup removes an agent from a group
func (gm *GroupManager) RemoveAgentFromGroup(groupID, agentID string) error {
	gm.mutex.Lock()
	defer gm.mutex.Unlock()

	return gm.removeAgentFromGroupUnsafe(groupID, agentID)
}

func (gm *GroupManager) removeAgentFromGroupUnsafe(groupID, agentID string) error {
	group, exists := gm.groups[groupID]
	if !exists {
		return fmt.Errorf("group not found")
	}

	for i, id := range group.AgentIDs {
		if id == agentID {
			group.AgentIDs = append(group.AgentIDs[:i], group.AgentIDs[i+1:]...)
			group.UpdatedAt = time.Now()
			delete(gm.agentMap, agentID)
			return nil
		}
	}

	return fmt.Errorf("agent not in group")
}

// GetGroupsByTag returns groups matching tags
func (gm *GroupManager) GetGroupsByTag(tag string) []*AgentGroup {
	gm.mutex.RLock()
	defer gm.mutex.RUnlock()

	var result []*AgentGroup
	for _, group := range gm.groups {
		for _, t := range group.Tags {
			if t == tag {
				result = append(result, group)
				break
			}
		}
	}
	return result
}

// GetAllGroups returns all groups
func (gm *GroupManager) GetAllGroups() map[string]*AgentGroup {
	gm.mutex.RLock()
	defer gm.mutex.RUnlock()

	result := make(map[string]*AgentGroup)
	for id, group := range gm.groups {
		// Return a copy to avoid race conditions
		groupCopy := *group
		result[id] = &groupCopy
	}
	return result
}

// GetGroup returns a specific group by ID
func (gm *GroupManager) GetGroup(groupID string) (*AgentGroup, bool) {
	gm.mutex.RLock()
	defer gm.mutex.RUnlock()

	group, exists := gm.groups[groupID]
	if !exists {
		return nil, false
	}

	// Return a copy to avoid race conditions
	groupCopy := *group
	return &groupCopy, true
}

// AutoGroupByOS automatically groups agents by operating system
func (gm *GroupManager) AutoGroupByOS(monitor *AgentMonitor) {
	agents := monitor.GetAllAgents()
	osGroups := make(map[string]*AgentGroup)

	for _, agent := range agents {
		groupName := fmt.Sprintf("OS_%s", agent.OS)

		var group *AgentGroup
		var exists bool

		gm.mutex.RLock()
		for _, g := range gm.groups {
			if g.Name == groupName {
				group = g
				exists = true
				break
			}
		}
		gm.mutex.RUnlock()

		if !exists {
			group = gm.CreateGroup(groupName, fmt.Sprintf("Auto-grouped %s agents", agent.OS), []string{"auto", "os"})
			osGroups[agent.OS] = group
		}

		gm.AddAgentToGroup(group.ID, agent.ID)
	}
}

// ExecuteBulkCommand executes command on multiple agents
func (gm *GroupManager) ExecuteBulkCommand(req *BulkCommandRequest, cmdQueue CommandQueueInterface) *BulkCommandResult {
	gm.mutex.RLock()
	defer gm.mutex.RUnlock()

	var targetAgents []string

	if req.GroupID != "" {
		if group, exists := gm.groups[req.GroupID]; exists {
			targetAgents = group.AgentIDs
		}
	} else {
		targetAgents = req.AgentIDs
	}

	if req.MaxConcurrent == 0 {
		req.MaxConcurrent = 10
	}

	result := &BulkCommandResult{
		TaskID:  generateUUID(),
		Status:  "running",
		Total:   len(targetAgents),
		Results: make(map[string]*types.Command),
	}

	// Execute commands with concurrency control
	go gm.executeBulkAsync(targetAgents, req, cmdQueue, result)

	return result
}

func (gm *GroupManager) executeBulkAsync(agentIDs []string, req *BulkCommandRequest, cmdQueue CommandQueueInterface, result *BulkCommandResult) {
	semaphore := make(chan struct{}, req.MaxConcurrent)
	var wg sync.WaitGroup

	for _, agentID := range agentIDs {
		wg.Add(1)
		go func(aid string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			cmd := &types.Command{
				ID:        generateUUID(),
				AgentID:   aid,
				Command:   req.Command,
				Timeout:   req.Timeout,
				CreatedAt: time.Now(),
				Status:    "pending",
			}

			// Add command to queue
			if err := cmdQueue.Add(aid, cmd); err != nil {
				// If failed to add to queue, mark as failed
				cmd.Status = "failed"
				cmd.Error = fmt.Sprintf("Failed to queue command: %v", err)
				cmd.CompletedAt = time.Now()
			}

			// Store result
			result.Results[aid] = cmd
		}(agentID)
	}

	wg.Wait()
	result.Status = "completed"

	// Update counters
	for _, cmd := range result.Results {
		if cmd.Status == "failed" {
			result.Failed++
		} else {
			result.Completed++
		}
	}
}

// DeleteGroup deletes a group
func (gm *GroupManager) DeleteGroup(groupID string) error {
	gm.mutex.Lock()
	defer gm.mutex.Unlock()

	group, exists := gm.groups[groupID]
	if !exists {
		return fmt.Errorf("group not found")
	}

	// Remove all agents from the group
	for _, agentID := range group.AgentIDs {
		delete(gm.agentMap, agentID)
	}

	// Delete the group
	delete(gm.groups, groupID)
	return nil
}

// UpdateGroup updates group information
func (gm *GroupManager) UpdateGroup(groupID string, name, description string, tags []string) error {
	gm.mutex.Lock()
	defer gm.mutex.Unlock()

	group, exists := gm.groups[groupID]
	if !exists {
		return fmt.Errorf("group not found")
	}

	if name != "" {
		group.Name = name
	}
	if description != "" {
		group.Description = description
	}
	if tags != nil {
		group.Tags = tags
	}
	group.UpdatedAt = time.Now()

	return nil
}

// GetAgentGroup returns the group ID for an agent
func (gm *GroupManager) GetAgentGroup(agentID string) (string, bool) {
	gm.mutex.RLock()
	defer gm.mutex.RUnlock()

	groupID, exists := gm.agentMap[agentID]
	return groupID, exists
}

// GetGroupStats returns statistics about groups
func (gm *GroupManager) GetGroupStats() map[string]interface{} {
	gm.mutex.RLock()
	defer gm.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_groups":     len(gm.groups),
		"total_agents":     len(gm.agentMap),
		"groups_by_tag":    make(map[string]int),
		"agents_per_group": make(map[string]int),
	}

	tagCount := make(map[string]int)
	for _, group := range gm.groups {
		stats["agents_per_group"].(map[string]int)[group.Name] = len(group.AgentIDs)

		for _, tag := range group.Tags {
			tagCount[tag]++
		}
	}

	stats["groups_by_tag"] = tagCount
	return stats
}

// generateUUID generates a unique identifier
func generateUUID() string {
	// Generate 16 random bytes
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback to timestamp-based UUID if crypto/rand fails
		now := time.Now().UnixNano()
		randomInt, _ := rand.Int(rand.Reader, big.NewInt(1000000))
		return fmt.Sprintf("%d-%d", now, randomInt.Int64())
	}

	// Set version and variant bits
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant 10

	return fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
