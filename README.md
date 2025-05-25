# Taburtuai C2 Framework

<div align="center">

![Taburtuai Logo](https://img.shields.io/badge/Taburtuai-C2%20Framework-red?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.0--Phase1-blue?style=for-the-badge)
![Go Version](https://img.shields.io/badge/Go-1.21+-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-Educational-yellow?style=for-the-badge)

**A modern, cross-platform Command and Control (C2) framework for cybersecurity research and education.**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Architecture](#-architecture) • [Documentation](#-documentation)

</div>

---

## ⚠️ **DISCLAIMER**

This tool is developed for **educational purposes**, **authorized penetration testing**, and **cybersecurity research** only. The developers are not responsible for any misuse or illegal activities. Always ensure you have explicit permission before testing on any systems.

---

## 🎯 **Features**

### **Phase 1 (Current) - Foundation**
- ✅ **Cross-Platform Agent Support** - Windows, Linux, macOS
- ✅ **UUID-Based Agent Tracking** - Unique identification for each implant
- ✅ **Real-Time Dashboard** - Web-based monitoring interface
- ✅ **Command Line Interface** - Comprehensive CLI for operations
- ✅ **RESTful API** - Complete API for automation and integration
- ✅ **Multi-Threaded Server** - High-performance concurrent operations
- ✅ **Automated Build System** - One-command agent generation
- ✅ **Flexible Configuration** - Customizable server and agent settings
- ✅ **Status Monitoring** - Real-time agent health and activity tracking
- ✅ **Comprehensive Logging** - Detailed operational logs

### **Phase 2 (Planned) - Core Operations**
- 🚧 **Command Execution** - Remote command execution on agents
- 🚧 **File Operations** - Upload/download capabilities
- 🚧 **Process Management** - Start/stop/monitor processes
- 🚧 **Network Discovery** - Internal network reconnaissance
- 🚧 **Persistence Mechanisms** - Auto-start and service installation

### **Phase 3+ (Future) - Advanced Features**
- 🔮 **Lateral Movement** - Network traversal capabilities
- 🔮 **Credential Harvesting** - Extract saved credentials
- 🔮 **Anti-Detection** - Evasion and stealth techniques
- 🔮 **Multi-User Support** - Team collaboration features

---

## 🚀 **Quick Start**

### **Prerequisites**
- Go 1.21 or higher
- Git
- Basic understanding of C2 frameworks

### **Installation**
```bash
# Clone the repository
git clone https://github.com/mjopsec/taburtuaiC2.git
cd taburtuaiC2

# Initialize Go modules
go mod init github.com/mjopsec/taburtuaiC2
go mod tidy

# Build the server
go build -o bin/taburtuai-server ./server/

# Build the CLI
go build -o bin/taburtuai-cli ./cli/

# Make scripts executable
chmod +x scripts/*.sh
```

### **Basic Usage**
```bash
# 1. Start the C2 server
./bin/taburtuai-server

# 2. Build an agent for Windows
./scripts/build_agent.sh -s http://your-server-ip:8080 -o windows

# 3. Monitor agents via CLI
./bin/taburtuai-cli agents list

# 4. Access web dashboard
firefox http://localhost:8080
```

---

## 📖 **Detailed Usage**

### **Server Operations**

#### **Starting the Server**
```bash
# Default configuration (localhost:8080)
./bin/taburtuai-server

# Custom port
./bin/taburtuai-server -port 9090

# Verbose logging
./bin/taburtuai-server -verbose
```

#### **Server Configuration**
The server automatically creates configuration files and logs in:
- `config/` - Configuration files
- `logs/` - Server and operation logs
- `web/` - Dashboard static files

### **Agent Building**

#### **Basic Agent Build**
```bash
# Windows agent
./scripts/build_agent.sh -o windows

# Linux agent  
./scripts/build_agent.sh -o linux

# macOS agent
./scripts/build_agent.sh -o darwin
```

#### **Advanced Agent Configuration**
```bash
# Custom server and encryption
./scripts/build_agent.sh \
  -s https://your-domain.com:8443 \
  -k "YourEncryptionKey" \
  -i 60 \
  -o windows \
  -S \
  -c

# Parameters:
# -s: Server URL
# -k: Encryption key
# -i: Beacon interval (seconds)
# -o: Target OS (windows/linux/darwin)
# -S: Enable stealth compilation
# -c: Compress with UPX
```

### **CLI Management**

#### **Agent Management**
```bash
# List all agents
./bin/taburtuai-cli agents list

# Show detailed agent information
./bin/taburtuai-cli agents show <agent-id>

# Monitor server statistics
./bin/taburtuai-cli stats

# View recent logs
./bin/taburtuai-cli logs --limit 50
```

#### **Command Operations (Phase 2)**
```bash
# Execute command (placeholder in Phase 1)
./bin/taburtuai-cli cmd <agent-id> "whoami"

# View command history
./bin/taburtuai-cli history <agent-id>
```

#### **CLI Configuration**
```bash
# Custom server
./bin/taburtuai-cli -s http://192.168.1.100:8080 agents list

# With API key
./bin/taburtuai-cli -k your-api-key agents list

# Verbose output
./bin/taburtuai-cli -v agents list
```

### **Web Dashboard**

Access the dashboard at `http://your-server:8080` for:
- Real-time agent monitoring
- Server statistics and health
- Visual agent status overview
- Quick operation controls

---

## 🏗️ **Architecture**

### **Component Overview**
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│                 │    │                 │    │                 │
│     Agents      │◄──►│   C2 Server     │◄──►│  Management     │
│   (Implants)    │    │                 │    │    (CLI/Web)    │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                        │                        │
        │                        │                        │
   ┌─────────┐              ┌─────────┐              ┌─────────┐
   │Windows  │              │REST API │              │Dashboard│
   │Linux    │              │WebSocket│              │CLI Tool │
   │macOS    │              │Logging  │              │Metrics  │
   └─────────┘              └─────────┘              └─────────┘
```

### **Directory Structure**
```
taburtuaiC2/
├── server/                 # C2 Server implementation
│   ├── main.go            # Server entry point
│   └── handlers.go        # HTTP handlers
├── cli/                   # Command line interface
│   └── main.go            # CLI implementation
├── agent/                 # Agent source code (generated)
├── scripts/               # Build and utility scripts
│   ├── build_agent.sh     # Agent build script
│   └── setup.sh           # Environment setup
├── web/                   # Dashboard static files
│   ├── templates/         # HTML templates
│   └── static/            # CSS, JS, assets
├── config/                # Configuration files (generated)
├── logs/                  # Log files (generated)
├── bin/                   # Compiled binaries (generated)
└── docs/                  # Documentation
```

### **Communication Flow**
1. **Agent Registration**: Agents send checkin requests with system info
2. **Status Updates**: Periodic heartbeats maintain connection status
3. **Command Dispatch**: Server queues commands for agent retrieval
4. **Result Collection**: Agents return command results via API
5. **Management Interface**: CLI/Web dashboard for monitoring and control

---

## 🔧 **API Reference**

### **Server Endpoints**

#### **Agent Management**
- `POST /api/v1/checkin` - Agent registration and heartbeat
- `GET /api/v1/agents` - List all agents
- `GET /api/v1/agents/{id}` - Get agent details
- `DELETE /api/v1/agents/{id}` - Remove agent

#### **System Information**
- `GET /api/v1/health` - Server health check
- `GET /api/v1/stats` - Server statistics
- `GET /api/v1/logs` - Recent server logs

#### **Operations (Phase 2)**
- `POST /api/v1/agents/{id}/command` - Execute command
- `GET /api/v1/agents/{id}/tasks` - Get pending tasks
- `GET /api/v1/history/{id}` - Command history

### **Request/Response Examples**

#### **Agent Checkin**
```bash
curl -X POST http://localhost:8080/api/v1/checkin \
  -H "Content-Type: application/json" \
  -d '{
    "id": "f608eacb-0a6b-4ff3-8c8a-9d3395e887b5",
    "hostname": "DESKTOP-PC",
    "username": "user",
    "os": "windows",
    "architecture": "amd64",
    "process_id": 1234
  }'
```

#### **List Agents**
```bash
curl http://localhost:8080/api/v1/agents | jq '.'
```

---

## 🛡️ **Security Considerations**

### **Current Implementation**
- UUID-based agent identification
- HTTP/HTTPS communication support
- Configurable encryption keys
- Server access logging

### **Recommended Practices**
1. **Use HTTPS** in production environments
2. **Change default encryption keys** before deployment
3. **Implement network segmentation** for C2 infrastructure
4. **Monitor and log** all operations
5. **Regular security updates** and key rotation

### **Future Security Enhancements (Phase 2+)**
- End-to-end encryption for all communications
- Certificate pinning for HTTPS
- Traffic obfuscation and domain fronting
- Anti-analysis and sandbox detection

---

## 🧪 **Testing & Development**

### **Running Tests**
```bash
# Test server connectivity
curl http://localhost:8080/api/v1/health

# Test agent build
./scripts/build_agent.sh -o linux

# Test CLI functionality
./bin/taburtuai-cli status
./bin/taburtuai-cli agents list
```

### **Development Environment**
```bash
# Enable verbose logging
export TABURTUAI_VERBOSE=true

# Custom configuration
export TABURTUAI_CONFIG=./config/custom.yaml

# Development server (auto-reload)
go run ./server/ -dev
```

### **Debugging**
- Server logs: `tail -f logs/taburtuai.log`
- Agent logs: Check agent output on target systems
- CLI verbose mode: `./bin/taburtuai-cli -v <command>`

---

## 🤝 **Contributing**

### **Development Guidelines**
1. Follow Go best practices and conventions
2. Add comprehensive tests for new features
3. Update documentation for any API changes
4. Ensure cross-platform compatibility
5. Maintain backward compatibility where possible

### **Feature Requests & Bug Reports**
Please use the GitHub Issues tab to:
- Report bugs with detailed reproduction steps
- Request new features with use case descriptions
- Suggest improvements to existing functionality

### **Pull Request Process**
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📚 **Documentation**

### **Additional Resources**
- [Agent Development Guide](docs/agent-development.md)
- [Server Configuration](docs/server-config.md)
- [API Documentation](docs/api-reference.md)
- [Deployment Guide](docs/deployment.md)
- [Troubleshooting](docs/troubleshooting.md)

### **Learning Resources**
- [C2 Framework Fundamentals](docs/c2-fundamentals.md)
- [Security Best Practices](docs/security-guide.md)
- [Advanced Usage Examples](docs/examples.md)

---

## 🗺️ **Roadmap**

### **Phase 1 - Foundation** ✅
- [x] Core server infrastructure
- [x] Agent management system
- [x] CLI and web interfaces
- [x] Build automation
- [x] Basic monitoring and logging

### **Phase 2 - Core Operations** 🚧
- [ ] Command execution engine
- [ ] File transfer capabilities
- [ ] Process management
- [ ] Network discovery
- [ ] Persistence mechanisms

### **Phase 3 - Advanced Features** 🔮
- [ ] Lateral movement
- [ ] Credential harvesting
- [ ] Anti-detection techniques
- [ ] Advanced evasion
- [ ] Multi-stage payloads

### **Phase 4 - Enterprise** 🔮
- [ ] Multi-user support
- [ ] Role-based access control
- [ ] Campaign management
- [ ] Advanced reporting
- [ ] Third-party integrations

---

## ⚖️ **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Educational Use Only**: This software is intended for educational purposes, authorized penetration testing, and cybersecurity research. Users are responsible for complying with all applicable laws and regulations.

---

## 👥 **Authors & Acknowledgments**

- **Primary Developer**: [Your Name](https://github.com/mjopsec)
- **Contributors**: See [CONTRIBUTORS.md](CONTRIBUTORS.md)

### **Special Thanks**
- Go community for excellent tooling and libraries
- Cybersecurity research community for inspiration
- Beta testers and early adopters

---

## 🔗 **Links**

- [GitHub Repository](https://github.com/mjopsec/taburtuaiC2)
- [Documentation](https://github.com/mjopsec/taburtuaiC2/docs)
- [Issue Tracker](https://github.com/mjopsec/taburtuaiC2/issues)
- [Releases](https://github.com/mjopsec/taburtuaiC2/releases)

---

<div align="center">

**Created with ❤️ fby MJ**

[![GitHub stars](https://img.shields.io/github/stars/mjopsec/taburtuaiC2?style=social)](https://github.com/mjopsec/taburtuaiC2/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/mjopsec/taburtuaiC2?style=social)](https://github.com/mjopsec/taburtuaiC2/network/members)

</div>
