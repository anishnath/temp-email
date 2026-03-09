package queue

import "latex-api/internal/model"

// Re-export for backward compatibility; use model package directly.
type CompileJob = model.CompileJob
type JobStatus = model.JobStatus

const (
	StatusPending   = model.StatusPending
	StatusCompiling = model.StatusCompiling
	StatusDone      = model.StatusDone
	StatusError     = model.StatusError
)
