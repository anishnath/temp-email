package queue

import (
	"latex-api/internal/compiler"
	"latex-api/internal/model"
)

// JobQueue is the buffered channel for compile jobs.
var JobQueue chan *model.CompileJob

// StartWorkerPool launches N worker goroutines.
func StartWorkerPool(n int) {
	JobQueue = make(chan *model.CompileJob, 100)
	for i := 0; i < n; i++ {
		go worker(JobQueue)
	}
}

func worker(jobs <-chan *model.CompileJob) {
	for job := range jobs {
		job.SetStatus(model.StatusCompiling)
		compiler.Compile(job)
	}
}
