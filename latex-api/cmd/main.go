package main

import (
	"log"
	"net/http"

	"latex-api/config"
	"latex-api/internal/api"
	"latex-api/queue"
)

func main() {
	cfg := config.Load()

	queue.StartWorkerPool(cfg.WorkerPoolSize)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	addr := "127.0.0.1:" + cfg.Port
	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	log.Printf("LaTeX API listening on %s (internal only)", addr)
	log.Fatal(srv.ListenAndServe())
}
