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

// CompileJob holds all state for a LaTeX or TikZ compilation.
type CompileJob struct {
	ID            string
	Status        Status
	Source        string // LaTeX full document
	Tikz          string // TikZ snippet (when set, use TikZ pipeline)
	WorkDir       string
	PDFPath       string        // set for LaTeX jobs
	SVGPath       string        // set for TikZ jobs
	LogLines      chan string   // streaming log lines
	Done          chan struct{} // closed when job finishes
	Error         string
	CreatedAt     time.Time
	FileIDs       []string // upload fileIds to copy into job dir before compile
	Packages      []string // extra \usepackage{} (TikZ jobs)
	TikzLibraries []string // extra \usetikzlibrary{} (TikZ jobs)
	GDLibraries   []string // \usegdlibrary{} for graph drawing (TikZ jobs)
	TikzBlock     string   // full \begin{tikzpicture}[opts]...\end{tikzpicture} (when from raw paste)

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

// SetDoneSVG sets SVG path and status to done (for TikZ jobs).
func (j *CompileJob) SetDoneSVG(svgPath string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.SVGPath = svgPath
	j.Status = StatusDone
}

// SetDoneSVGWithWarning sets SVG path and status to done but records a warning (e.g. latex exited non-zero but SVG was produced).
func (j *CompileJob) SetDoneSVGWithWarning(svgPath, warning string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.SVGPath = svgPath
	j.Status = StatusDone
	j.Error = warning
}

// NewTikzJob creates a new TikZ compile job.
// Use Tikz for inner content only, or TikzBlock for full \begin{tikzpicture}...\end{tikzpicture} block.
func NewTikzJob(tikz string, fileIDs []string, packages []string, tikzLibraries []string) *CompileJob {
	return &CompileJob{
		ID:            uuid.New().String(),
		Status:        StatusPending,
		Tikz:          tikz,
		FileIDs:       fileIDs,
		Packages:      packages,
		TikzLibraries: tikzLibraries,
		LogLines:      make(chan string, 256),
		Done:          make(chan struct{}),
		CreatedAt:     time.Now(),
	}
}

// NewTikzJobFromRaw creates a TikZ job from a parsed raw block.
func NewTikzJobFromRaw(tikzBlock string, fileIDs []string, packages []string, tikzLibraries []string, gdLibraries []string) *CompileJob {
	return &CompileJob{
		ID:            uuid.New().String(),
		Status:        StatusPending,
		TikzBlock:     tikzBlock,
		FileIDs:       fileIDs,
		Packages:      packages,
		TikzLibraries: tikzLibraries,
		GDLibraries:   gdLibraries,
		LogLines:      make(chan string, 256),
		Done:          make(chan struct{}),
		CreatedAt:     time.Now(),
	}
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
