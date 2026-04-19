package model

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// JobStatus represents the lifecycle state of a compile job.
type JobStatus string

const (
	StatusPending   JobStatus = "pending"
	StatusCompiling JobStatus = "compiling"
	StatusDone      JobStatus = "done"
	StatusError     JobStatus = "error"
)

// CompileJob holds all state for a LaTeX compilation.
type CompileJob struct {
	ID        string
	Status    JobStatus
	Source    string
	FileIDs   []string // uploaded file IDs to copy into job dir
	WorkDir   string
	PDFPath   string
	LogLines  chan string   // streaming log lines
	Done      chan struct{} // closed when job finishes
	Error     string
	CreatedAt time.Time

	mu sync.RWMutex
}

// NewCompileJob creates a new job with the given source and optional file IDs.
func NewCompileJob(source string, fileIDs []string) *CompileJob {
	return &CompileJob{
		ID:        uuid.New().String(),
		Status:    StatusPending,
		Source:    source,
		FileIDs:   fileIDs,
		LogLines:  make(chan string, 256),
		Done:      make(chan struct{}),
		CreatedAt: time.Now(),
	}
}

// SetStatus updates job status (thread-safe).
func (j *CompileJob) SetStatus(s JobStatus) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Status = s
}

// GetStatus returns current job status (thread-safe).
func (j *CompileJob) GetStatus() JobStatus {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.Status
}

// SetError sets error message and status to error.
func (j *CompileJob) SetError(err string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Error = err
	j.Status = StatusError
}

// SetDone sets PDF path and status to done.
func (j *CompileJob) SetDone(pdfPath string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.PDFPath = pdfPath
	j.Status = StatusDone
}

// Job registry using sync.Map for concurrent access.
var Jobs sync.Map

// RegisterJob stores a job in the registry.
func RegisterJob(job *CompileJob) {
	Jobs.Store(job.ID, job)
}

// GetJob retrieves a job by ID.
func GetJob(jobID string) (*CompileJob, bool) {
	v, ok := Jobs.Load(jobID)
	if !ok {
		return nil, false
	}
	return v.(*CompileJob), true
}

// DeleteJob removes a job from the registry.
func DeleteJob(jobID string) {
	Jobs.Delete(jobID)
}
