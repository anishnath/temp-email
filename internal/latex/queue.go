package latex

import (
	"temp-email/internal/latex/compiler"
	"temp-email/internal/latex/job"
)

// JobQueue is the buffered channel for compile jobs.
var JobQueue chan *job.CompileJob

// StartWorkerPool launches N worker goroutines.
func StartWorkerPool(n int) {
	JobQueue = make(chan *job.CompileJob, 100)
	for i := 0; i < n; i++ {
		go worker(JobQueue)
	}
}

func worker(jobs <-chan *job.CompileJob) {
	for j := range jobs {
		j.SetStatus(job.StatusCompiling)
		compiler.Compile(j)
	}
}
