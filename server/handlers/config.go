package handlers

import (
	"encoding/json"
	"log"
	"net/http"
)

// ConfigData menyesuaikan agent/config.go
type ConfigData struct {
	ServerURL      string `json:"server_url"`
	EncryptionKey  string `json:"encryption_key"`
	BeaconInterval int    `json:"beacon_interval"`
}

// Hard-coded atau bisa kita load dari file
var GlobalConfig = ConfigData{
	ServerURL:      "http://127.0.0.1:8080",
	EncryptionKey:  "SpookyOrcaC2AES1",
	BeaconInterval: 5,
}

func GetConfigHandler(w http.ResponseWriter, r *http.Request) {
	// Optionally, kita bisa parse param dari r.URL.Query()
	// untuk menyesuaikan config per agent ID?
	// id := r.URL.Query().Get("id")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(GlobalConfig)
	log.Println("[+] Sent runtime config to agent")
}
