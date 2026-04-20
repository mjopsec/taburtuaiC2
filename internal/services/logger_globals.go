package services

// GlobalLogger is the shared logger instance used across services
var GlobalLogger *Logger

// Package-level convenience wrappers — use only when a *Logger is not in scope

func LogInfo(category LogCategory, message, agentID string) {
	if GlobalLogger != nil {
		GlobalLogger.Info(category, message, agentID, "", nil)
	}
}

func LogWarn(category LogCategory, message, agentID string) {
	if GlobalLogger != nil {
		GlobalLogger.Warn(category, message, agentID, "", nil)
	}
}

func LogError(category LogCategory, message, agentID string) {
	if GlobalLogger != nil {
		GlobalLogger.Error(category, message, agentID, "", nil)
	}
}

func LogAgentActivity(agentID, action, clientIP string) {
	if GlobalLogger != nil {
		GlobalLogger.LogAgentConnection(agentID, action, clientIP)
	}
}

func LogCommand(agentID, command, result string, success bool) {
	if GlobalLogger != nil {
		GlobalLogger.LogCommandExecution(agentID, command, result, success)
	}
}

func LogFileOp(agentID, operation, filename, size string, success bool) {
	if GlobalLogger != nil {
		GlobalLogger.LogFileTransfer(agentID, operation, filename, size, success)
	}
}

func LogSecurityEvent(event, description, agentID, clientIP string, severity int) {
	if GlobalLogger != nil {
		GlobalLogger.LogSecurityEvent(event, description, agentID, clientIP, severity)
	}
}
