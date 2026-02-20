package job

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// Status represents the lifecycle state of a compile job.
type Status string

const (
	StatusPending   Status = "pending"
	StatusCompiling Status = "compiling"
	StatusDone      Status = "done"
	StatusError     Status = "error"
)

// CompileJob holds all state for a LaTeX compilation.
type CompileJob struct {
	ID        string
	Status    Status
	Source    string
	WorkDir   string
	PDFPath   string
	LogLines  chan string   // streaming log lines
	Done      chan struct{} // closed when job finishes
	Error     string
	CreatedAt time.Time
	FileIDs   []string // upload fileIds to copy into job dir before compile

	mu sync.RWMutex
}

// NewCompileJob creates a new job with the given source and optional fileIds from uploads.
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
func (j *CompileJob) SetStatus(s Status) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Status = s
}

// GetStatus returns current job status (thread-safe).
func (j *CompileJob) GetStatus() Status {
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

// SetDoneWithWarning sets PDF path and status to done, but records the first error/warning from the log.
// PDF was produced despite pdflatex exiting non-zero (nonstopmode continues past many error types).
func (j *CompileJob) SetDoneWithWarning(pdfPath, warning string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.PDFPath = pdfPath
	j.Status = StatusDone
	j.Error = warning
}

// Registry for concurrent access.
var registry sync.Map

// RegisterJob stores a job in the registry.
func RegisterJob(j *CompileJob) {
	registry.Store(j.ID, j)
}

// GetJob retrieves a job by ID.
func GetJob(jobID string) (*CompileJob, bool) {
	v, ok := registry.Load(jobID)
	if !ok {
		return nil, false
	}
	return v.(*CompileJob), true
}

// DeleteJob removes a job from the registry.
func DeleteJob(jobID string) {
	registry.Delete(jobID)
}
