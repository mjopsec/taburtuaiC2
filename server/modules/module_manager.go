// server/modules/module_manager.go
package modules

import (
	"context"
	"fmt"
	"plugin"
	"sync"
	"time"
)

// ModuleManager handles dynamic module loading and execution
type ModuleManager struct {
	modules    map[string]*Module
	categories map[string][]*Module
	mutex      sync.RWMutex
	config     *ModuleConfig
}

type ModuleConfig struct {
	ModulesDir      string
	EnableHotReload bool
	MaxConcurrent   int
	DefaultTimeout  time.Duration
}

// Module represents a loadable C2 module
type Module struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Author      string   `json:"author"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Tags        []string `json:"tags"`

	// Module metadata
	SupportedOS   []string `json:"supported_os"`
	RequiredPrivs string   `json:"required_privs"`
	Dependencies  []string `json:"dependencies"`

	// Execution configuration
	Timeout time.Duration `json:"timeout"`
	Async   bool          `json:"async"`
	Stealth bool          `json:"stealth"`

	// Module interface
	Interface      ModuleInterface `json:"-"`
	LoadedAt       time.Time       `json:"loaded_at"`
	LastExecuted   time.Time       `json:"last_executed"`
	ExecutionCount int             `json:"execution_count"`
}

// ModuleInterface defines the contract for all modules
type ModuleInterface interface {
	Initialize(config map[string]interface{}) error
	Execute(ctx context.Context, params *ModuleParams) (*ModuleResult, error)
	Cleanup() error
	GetInfo() *ModuleInfo
	Validate(params *ModuleParams) error
}

// ModuleParams contains execution parameters
type ModuleParams struct {
	AgentID string                 `json:"agent_id"`
	Target  string                 `json:"target,omitempty"`
	Options map[string]interface{} `json:"options"`
	Files   map[string][]byte      `json:"files,omitempty"`
	Timeout time.Duration          `json:"timeout"`
}

// ModuleResult contains execution results
type ModuleResult struct {
	Success   bool                   `json:"success"`
	Output    string                 `json:"output"`
	Error     string                 `json:"error,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Files     map[string][]byte      `json:"files,omitempty"`
	Artifacts []string               `json:"artifacts,omitempty"`
	Duration  time.Duration          `json:"duration"`
}

// ModuleInfo contains module metadata
type ModuleInfo struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	Author      string   `json:"author"`
	Category    string   `json:"category"`
	SupportedOS []string `json:"supported_os"`
}

func NewModuleManager(config *ModuleConfig) *ModuleManager {
	return &ModuleManager{
		modules:    make(map[string]*Module),
		categories: make(map[string][]*Module),
		config:     config,
	}
}

// LoadModule loads a module from a plugin file
func (mm *ModuleManager) LoadModule(pluginPath string) (*Module, error) {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	p, err := plugin.Open(pluginPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open plugin: %v", err)
	}

	// Get the module symbol
	sym, err := p.Lookup("Module")
	if err != nil {
		return nil, fmt.Errorf("module symbol not found: %v", err)
	}

	moduleInterface, ok := sym.(ModuleInterface)
	if !ok {
		return nil, fmt.Errorf("invalid module interface")
	}

	info := moduleInterface.GetInfo()
	module := &Module{
		ID:          generateModuleID(info.Name, info.Version),
		Name:        info.Name,
		Version:     info.Version,
		Author:      info.Author,
		Description: info.Description,
		Category:    info.Category,
		SupportedOS: info.SupportedOS,
		Interface:   moduleInterface,
		LoadedAt:    time.Now(),
	}

	// Initialize the module
	if err := moduleInterface.Initialize(nil); err != nil {
		return nil, fmt.Errorf("module initialization failed: %v", err)
	}

	mm.modules[module.ID] = module
	mm.categories[module.Category] = append(mm.categories[module.Category], module)

	return module, nil
}

// ExecuteModule executes a module with given parameters
func (mm *ModuleManager) ExecuteModule(moduleID string, params *ModuleParams) (*ModuleResult, error) {
	mm.mutex.RLock()
	module, exists := mm.modules[moduleID]
	mm.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("module not found: %s", moduleID)
	}

	// Validate parameters
	if err := module.Interface.Validate(params); err != nil {
		return nil, fmt.Errorf("parameter validation failed: %v", err)
	}

	// Set timeout
	timeout := params.Timeout
	if timeout == 0 {
		timeout = mm.config.DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	result, err := module.Interface.Execute(ctx, params)
	duration := time.Since(start)

	if result != nil {
		result.Duration = duration
	}

	// Update module statistics
	mm.mutex.Lock()
	module.LastExecuted = time.Now()
	module.ExecutionCount++
	mm.mutex.Unlock()

	return result, err
}

// GetModule retrieves a module by ID
func (mm *ModuleManager) GetModule(moduleID string) (*Module, bool) {
	mm.mutex.RLock()
	defer mm.mutex.RUnlock()

	module, exists := mm.modules[moduleID]
	return module, exists
}

// GetModulesByCategory returns modules in a specific category
func (mm *ModuleManager) GetModulesByCategory(category string) []*Module {
	mm.mutex.RLock()
	defer mm.mutex.RUnlock()

	return mm.categories[category]
}

// GetAllModules returns all loaded modules
func (mm *ModuleManager) GetAllModules() map[string]*Module {
	mm.mutex.RLock()
	defer mm.mutex.RUnlock()

	result := make(map[string]*Module)
	for id, module := range mm.modules {
		result[id] = module
	}
	return result
}

// UnloadModule unloads a module
func (mm *ModuleManager) UnloadModule(moduleID string) error {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	module, exists := mm.modules[moduleID]
	if !exists {
		return fmt.Errorf("module not found: %s", moduleID)
	}

	// Cleanup module
	if err := module.Interface.Cleanup(); err != nil {
		return fmt.Errorf("module cleanup failed: %v", err)
	}

	// Remove from maps
	delete(mm.modules, moduleID)

	// Remove from category
	categoryModules := mm.categories[module.Category]
	for i, m := range categoryModules {
		if m.ID == moduleID {
			mm.categories[module.Category] = append(categoryModules[:i], categoryModules[i+1:]...)
			break
		}
	}

	return nil
}

// Built-in modules

// PortScanModule implements network port scanning
type PortScanModule struct {
	name    string
	version string
}

func (psm *PortScanModule) Initialize(config map[string]interface{}) error {
	psm.name = "PortScanner"
	psm.version = "1.0.0"
	return nil
}

func (psm *PortScanModule) Execute(ctx context.Context, params *ModuleParams) (*ModuleResult, error) {
	target, ok := params.Options["target"].(string)
	if !ok {
		return &ModuleResult{
			Success: false,
			Error:   "target parameter required",
		}, nil
	}

	ports, ok := params.Options["ports"].([]interface{})
	if !ok {
		// Default ports
		ports = []interface{}{21, 22, 23, 25, 53, 80, 110, 443, 993, 995}
	}

	result := &ModuleResult{
		Success: true,
		Data:    make(map[string]interface{}),
	}

	openPorts := []int{}
	for _, p := range ports {
		port := int(p.(float64))
		if psm.isPortOpen(target, port) {
			openPorts = append(openPorts, port)
		}
	}

	result.Data["open_ports"] = openPorts
	result.Output = fmt.Sprintf("Found %d open ports on %s", len(openPorts), target)

	return result, nil
}

func (psm *PortScanModule) isPortOpen(host string, port int) bool {
	// Simplified port check implementation
	return false
}

func (psm *PortScanModule) Cleanup() error {
	return nil
}

func (psm *PortScanModule) GetInfo() *ModuleInfo {
	return &ModuleInfo{
		Name:        "PortScanner",
		Version:     "1.0.0",
		Description: "Network port scanner module",
		Author:      "Taburtuai Team",
		Category:    "reconnaissance",
		SupportedOS: []string{"windows", "linux", "darwin"},
	}
}

func (psm *PortScanModule) Validate(params *ModuleParams) error {
	if _, ok := params.Options["target"]; !ok {
		return fmt.Errorf("target parameter is required")
	}
	return nil
}

// FileSystemModule implements file system operations
type FileSystemModule struct {
	name    string
	version string
}

func (fsm *FileSystemModule) Initialize(config map[string]interface{}) error {
	fsm.name = "FileSystem"
	fsm.version = "1.0.0"
	return nil
}

func (fsm *FileSystemModule) Execute(ctx context.Context, params *ModuleParams) (*ModuleResult, error) {
	operation, ok := params.Options["operation"].(string)
	if !ok {
		return &ModuleResult{
			Success: false,
			Error:   "operation parameter required",
		}, nil
	}

	result := &ModuleResult{
		Success: true,
		Data:    make(map[string]interface{}),
	}

	switch operation {
	case "list":
		path, _ := params.Options["path"].(string)
		if path == "" {
			path = "."
		}
		files, err := fsm.listFiles(path)
		if err != nil {
			result.Success = false
			result.Error = err.Error()
		} else {
			result.Data["files"] = files
			result.Output = fmt.Sprintf("Listed %d items in %s", len(files), path)
		}

	case "search":
		pattern, _ := params.Options["pattern"].(string)
		path, _ := params.Options["path"].(string)
		if pattern == "" {
			result.Success = false
			result.Error = "pattern parameter required for search"
		} else {
			matches, err := fsm.searchFiles(path, pattern)
			if err != nil {
				result.Success = false
				result.Error = err.Error()
			} else {
				result.Data["matches"] = matches
				result.Output = fmt.Sprintf("Found %d matches for pattern '%s'", len(matches), pattern)
			}
		}

	default:
		result.Success = false
		result.Error = fmt.Sprintf("unknown operation: %s", operation)
	}

	return result, nil
}

func (fsm *FileSystemModule) listFiles(path string) ([]map[string]interface{}, error) {
	// Implementation for file listing
	return []map[string]interface{}{}, nil
}

func (fsm *FileSystemModule) searchFiles(path, pattern string) ([]string, error) {
	// Implementation for file searching
	return []string{}, nil
}

func (fsm *FileSystemModule) Cleanup() error {
	return nil
}

func (fsm *FileSystemModule) GetInfo() *ModuleInfo {
	return &ModuleInfo{
		Name:        "FileSystem",
		Version:     "1.0.0",
		Description: "File system operations module",
		Author:      "Taburtuai Team",
		Category:    "file_operations",
		SupportedOS: []string{"windows", "linux", "darwin"},
	}
}

func (fsm *FileSystemModule) Validate(params *ModuleParams) error {
	if _, ok := params.Options["operation"]; !ok {
		return fmt.Errorf("operation parameter is required")
	}
	return nil
}

// CredentialHarvestModule implements credential harvesting
type CredentialHarvestModule struct {
	name    string
	version string
}

func (chm *CredentialHarvestModule) Initialize(config map[string]interface{}) error {
	chm.name = "CredentialHarvester"
	chm.version = "1.0.0"
	return nil
}

func (chm *CredentialHarvestModule) Execute(ctx context.Context, params *ModuleParams) (*ModuleResult, error) {
	method, ok := params.Options["method"].(string)
	if !ok {
		method = "all"
	}

	result := &ModuleResult{
		Success: true,
		Data:    make(map[string]interface{}),
	}

	credentials := []map[string]string{}

	switch method {
	case "browser":
		creds, err := chm.harvestBrowserCredentials()
		if err != nil {
			result.Success = false
			result.Error = err.Error()
		} else {
			credentials = append(credentials, creds...)
		}

	case "registry":
		creds, err := chm.harvestRegistryCredentials()
		if err != nil {
			result.Success = false
			result.Error = err.Error()
		} else {
			credentials = append(credentials, creds...)
		}

	case "all":
		if browserCreds, err := chm.harvestBrowserCredentials(); err == nil {
			credentials = append(credentials, browserCreds...)
		}
		if regCreds, err := chm.harvestRegistryCredentials(); err == nil {
			credentials = append(credentials, regCreds...)
		}

	default:
		result.Success = false
		result.Error = fmt.Sprintf("unknown harvesting method: %s", method)
	}

	if result.Success {
		result.Data["credentials"] = credentials
		result.Output = fmt.Sprintf("Harvested %d credentials using method '%s'", len(credentials), method)
	}

	return result, nil
}

func (chm *CredentialHarvestModule) harvestBrowserCredentials() ([]map[string]string, error) {
	// Implementation for browser credential harvesting
	return []map[string]string{}, nil
}

func (chm *CredentialHarvestModule) harvestRegistryCredentials() ([]map[string]string, error) {
	// Implementation for registry credential harvesting
	return []map[string]string{}, nil
}

func (chm *CredentialHarvestModule) Cleanup() error {
	return nil
}

func (chm *CredentialHarvestModule) GetInfo() *ModuleInfo {
	return &ModuleInfo{
		Name:        "CredentialHarvester",
		Version:     "1.0.0",
		Description: "Credential harvesting module",
		Author:      "Taburtuai Team",
		Category:    "credential_access",
		SupportedOS: []string{"windows", "linux", "darwin"},
	}
}

func (chm *CredentialHarvestModule) Validate(params *ModuleParams) error {
	return nil
}

// Helper functions
func generateModuleID(name, version string) string {
	return fmt.Sprintf("%s_%s_%d", name, version, time.Now().Unix())
}

// RegisterBuiltinModules registers all built-in modules
func (mm *ModuleManager) RegisterBuiltinModules() error {
	modules := []ModuleInterface{
		&PortScanModule{},
		&FileSystemModule{},
		&CredentialHarvestModule{},
	}

	for _, moduleInterface := range modules {
		if err := moduleInterface.Initialize(nil); err != nil {
			return fmt.Errorf("failed to initialize builtin module: %v", err)
		}

		info := moduleInterface.GetInfo()
		module := &Module{
			ID:          generateModuleID(info.Name, info.Version),
			Name:        info.Name,
			Version:     info.Version,
			Author:      info.Author,
			Description: info.Description,
			Category:    info.Category,
			SupportedOS: info.SupportedOS,
			Interface:   moduleInterface,
			LoadedAt:    time.Now(),
		}

		mm.modules[module.ID] = module
		mm.categories[module.Category] = append(mm.categories[module.Category], module)
	}

	return nil
}
