package parallel

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/llm"
	"github.com/dimajoyti/hackai/pkg/logger"
)

// Branch represents a parallel execution branch
type Branch struct {
	ID          string                 `json:"id"`
	ParentID    string                 `json:"parent_id"`
	StartNodeID string                 `json:"start_node_id"`
	State       llm.GraphState         `json:"state"`
	Status      BranchStatus           `json:"status"`
	CreatedAt   time.Time              `json:"created_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Result      *BranchResult          `json:"result,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// BranchStatus represents the status of a branch execution
type BranchStatus string

const (
	BranchStatusPending   BranchStatus = "pending"
	BranchStatusRunning   BranchStatus = "running"
	BranchStatusCompleted BranchStatus = "completed"
	BranchStatusFailed    BranchStatus = "failed"
	BranchStatusCancelled BranchStatus = "cancelled"
)

// BranchResult holds the result of a branch execution
type BranchResult struct {
	State    llm.GraphState         `json:"state"`
	Output   interface{}            `json:"output"`
	Error    *string                `json:"error,omitempty"`
	Metadata map[string]interface{} `json:"metadata"`
}

// Task represents a task to be executed by a worker
type Task struct {
	ID       string
	BranchID string
	NodeID   string
	State    llm.GraphState
	Context  context.Context
	Callback func(*TaskResult)
}

// TaskResult holds the result of task execution
type TaskResult struct {
	TaskID   string
	BranchID string
	State    llm.GraphState
	Output   interface{}
	Error    error
	Duration time.Duration
}

// WorkerPool manages a pool of workers for parallel execution
type WorkerPool struct {
	workers   []*Worker
	taskQueue chan *Task
	config    WorkerPoolConfig
	logger    *logger.Logger
	mutex     sync.RWMutex
	running   bool
	stopChan  chan struct{}
	wg        sync.WaitGroup
}

// WorkerPoolConfig holds worker pool configuration
type WorkerPoolConfig struct {
	MaxWorkers      int           `json:"max_workers"`
	QueueSize       int           `json:"queue_size"`
	TaskTimeout     time.Duration `json:"task_timeout"`
	IdleTimeout     time.Duration `json:"idle_timeout"`
	EnableMetrics   bool          `json:"enable_metrics"`
}

// Worker represents a single worker in the pool
type Worker struct {
	ID       string
	pool     *WorkerPool
	taskChan chan *Task
	stopChan chan struct{}
	logger   *logger.Logger
	metrics  *WorkerMetrics
}

// WorkerMetrics holds metrics for a worker
type WorkerMetrics struct {
	TasksProcessed int64         `json:"tasks_processed"`
	TotalDuration  time.Duration `json:"total_duration"`
	LastTaskAt     time.Time     `json:"last_task_at"`
	ErrorCount     int64         `json:"error_count"`
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(maxWorkers int, logger *logger.Logger) *WorkerPool {
	config := WorkerPoolConfig{
		MaxWorkers:    maxWorkers,
		QueueSize:     maxWorkers * 10,
		TaskTimeout:   30 * time.Second,
		IdleTimeout:   5 * time.Minute,
		EnableMetrics: true,
	}

	return &WorkerPool{
		workers:   make([]*Worker, 0, maxWorkers),
		taskQueue: make(chan *Task, config.QueueSize),
		config:    config,
		logger:    logger,
		stopChan:  make(chan struct{}),
	}
}

// Start starts the worker pool
func (wp *WorkerPool) Start(ctx context.Context) error {
	wp.mutex.Lock()
	defer wp.mutex.Unlock()

	if wp.running {
		return fmt.Errorf("worker pool already running")
	}

	// Create workers
	for i := 0; i < wp.config.MaxWorkers; i++ {
		worker := &Worker{
			ID:       fmt.Sprintf("worker-%d", i),
			pool:     wp,
			taskChan: make(chan *Task, 1),
			stopChan: make(chan struct{}),
			logger:   wp.logger,
			metrics:  &WorkerMetrics{},
		}
		wp.workers = append(wp.workers, worker)

		// Start worker
		wp.wg.Add(1)
		go worker.run(ctx)
	}

	// Start task distributor
	wp.wg.Add(1)
	go wp.distributeTask(ctx)

	wp.running = true
	wp.logger.Info("Worker pool started", "workers", wp.config.MaxWorkers)

	return nil
}

// Stop stops the worker pool
func (wp *WorkerPool) Stop() error {
	wp.mutex.Lock()
	defer wp.mutex.Unlock()

	if !wp.running {
		return fmt.Errorf("worker pool not running")
	}

	close(wp.stopChan)
	wp.wg.Wait()

	wp.running = false
	wp.logger.Info("Worker pool stopped")

	return nil
}

// SubmitTask submits a task to the worker pool
func (wp *WorkerPool) SubmitTask(task *Task) error {
	if !wp.running {
		return fmt.Errorf("worker pool not running")
	}

	select {
	case wp.taskQueue <- task:
		return nil
	default:
		return fmt.Errorf("task queue full")
	}
}

// distributeTask distributes tasks to workers
func (wp *WorkerPool) distributeTask(ctx context.Context) {
	defer wp.wg.Done()

	for {
		select {
		case task := <-wp.taskQueue:
			// Find available worker
			worker := wp.findAvailableWorker()
			if worker != nil {
				select {
				case worker.taskChan <- task:
					// Task assigned successfully
				default:
					// Worker busy, put task back in queue
					select {
					case wp.taskQueue <- task:
					default:
						wp.logger.Error("Failed to reassign task, queue full")
					}
				}
			} else {
				// No available workers, put task back in queue
				select {
				case wp.taskQueue <- task:
				default:
					wp.logger.Error("No available workers and queue full")
				}
			}

		case <-wp.stopChan:
			return

		case <-ctx.Done():
			return
		}
	}
}

// findAvailableWorker finds an available worker
func (wp *WorkerPool) findAvailableWorker() *Worker {
	for _, worker := range wp.workers {
		select {
		case <-worker.taskChan:
			// Worker has a task, not available
		default:
			// Worker available
			return worker
		}
	}
	return nil
}

// run runs the worker
func (w *Worker) run(ctx context.Context) {
	defer w.pool.wg.Done()

	for {
		select {
		case task := <-w.taskChan:
			w.processTask(ctx, task)

		case <-w.stopChan:
			return

		case <-ctx.Done():
			return

		case <-time.After(w.pool.config.IdleTimeout):
			// Worker idle timeout
			w.logger.Debug("Worker idle timeout", "worker_id", w.ID)
		}
	}
}

// processTask processes a single task
func (w *Worker) processTask(ctx context.Context, task *Task) {
	startTime := time.Now()
	w.metrics.LastTaskAt = startTime

	// Create task context with timeout
	taskCtx, cancel := context.WithTimeout(ctx, w.pool.config.TaskTimeout)
	defer cancel()

	// Execute task
	result := &TaskResult{
		TaskID:   task.ID,
		BranchID: task.BranchID,
		State:    task.State,
	}

	// Simulate task execution (in real implementation, this would execute the actual node)
	select {
	case <-time.After(100 * time.Millisecond): // Simulate work
		result.Output = "Task completed successfully"
		w.metrics.TasksProcessed++

	case <-taskCtx.Done():
		result.Error = taskCtx.Err()
		w.metrics.ErrorCount++
	}

	result.Duration = time.Since(startTime)
	w.metrics.TotalDuration += result.Duration

	// Call callback if provided
	if task.Callback != nil {
		task.Callback(result)
	}

	w.logger.Debug("Task processed",
		"worker_id", w.ID,
		"task_id", task.ID,
		"duration", result.Duration,
		"error", result.Error)
}

// TaskScheduler schedules and executes tasks
type TaskScheduler struct {
	logger *logger.Logger
}

// NewTaskScheduler creates a new task scheduler
func NewTaskScheduler(logger *logger.Logger) *TaskScheduler {
	return &TaskScheduler{
		logger: logger,
	}
}

// ScheduleAndExecute schedules and executes tasks
func (ts *TaskScheduler) ScheduleAndExecute(ctx context.Context, tasks []*Task) ([]*TaskResult, error) {
	results := make([]*TaskResult, 0, len(tasks))
	resultChan := make(chan *TaskResult, len(tasks))
	var wg sync.WaitGroup

	// Execute tasks
	for _, task := range tasks {
		wg.Add(1)
		go func(t *Task) {
			defer wg.Done()

			// Set callback to collect results
			t.Callback = func(result *TaskResult) {
				resultChan <- result
			}

			// Simulate task execution
			startTime := time.Now()
			result := &TaskResult{
				TaskID:   t.ID,
				BranchID: t.BranchID,
				State:    t.State,
				Output:   "Task completed",
				Duration: time.Since(startTime),
			}

			t.Callback(result)
		}(task)
	}

	// Wait for all tasks to complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	for result := range resultChan {
		results = append(results, result)
	}

	return results, nil
}

// ExecutionSynchronizer synchronizes parallel execution
type ExecutionSynchronizer struct {
	logger *logger.Logger
}

// NewExecutionSynchronizer creates a new execution synchronizer
func NewExecutionSynchronizer(logger *logger.Logger) *ExecutionSynchronizer {
	return &ExecutionSynchronizer{
		logger: logger,
	}
}

// Synchronize synchronizes execution results
func (es *ExecutionSynchronizer) Synchronize(ctx context.Context, results []*TaskResult) ([]*TaskResult, error) {
	// For now, just return the results as-is
	// In a real implementation, this would handle synchronization logic
	return results, nil
}

// ResultMerger merges execution results
type ResultMerger struct {
	logger *logger.Logger
}

// NewResultMerger creates a new result merger
func NewResultMerger(logger *logger.Logger) *ResultMerger {
	return &ResultMerger{
		logger: logger,
	}
}

// MergedResult holds the result of merging multiple results
type MergedResult struct {
	State       llm.GraphState         `json:"state"`
	Conflicts   []StateConflict        `json:"conflicts"`
	Resolution  ConflictResolution     `json:"resolution"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// StateConflict represents a conflict between states
type StateConflict struct {
	Key      string           `json:"key"`
	Values   []ConflictValue  `json:"values"`
	Type     ConflictType     `json:"type"`
	Severity ConflictSeverity `json:"severity"`
}

// ConflictValue represents a conflicting value
type ConflictValue struct {
	BranchID string      `json:"branch_id"`
	Value    interface{} `json:"value"`
	Priority int         `json:"priority"`
}

// ConflictType represents the type of conflict
type ConflictType string

const (
	ConflictTypeValue     ConflictType = "value"
	ConflictTypeStructure ConflictType = "structure"
	ConflictTypeType      ConflictType = "type"
)

// ConflictSeverity represents the severity of a conflict
type ConflictSeverity string

const (
	ConflictSeverityLow      ConflictSeverity = "low"
	ConflictSeverityMedium   ConflictSeverity = "medium"
	ConflictSeverityHigh     ConflictSeverity = "high"
	ConflictSeverityCritical ConflictSeverity = "critical"
)

// ConflictResolution represents how a conflict was resolved
type ConflictResolution struct {
	Strategy    ResolutionStrategy     `json:"strategy"`
	ChosenValue interface{}            `json:"chosen_value"`
	Reason      string                 `json:"reason"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ResolutionStrategy represents the strategy used to resolve conflicts
type ResolutionStrategy string

const (
	ResolutionStrategyPriority ResolutionStrategy = "priority"
	ResolutionStrategyMajority ResolutionStrategy = "majority"
	ResolutionStrategyMerge    ResolutionStrategy = "merge"
	ResolutionStrategyCustom   ResolutionStrategy = "custom"
)

// MergeResults merges multiple task results
func (rm *ResultMerger) MergeResults(ctx context.Context, results []*TaskResult) (*MergedResult, error) {
	if len(results) == 0 {
		return &MergedResult{
			State:    llm.GraphState{},
			Metadata: make(map[string]interface{}),
		}, nil
	}

	// For now, just use the first result's state
	// In a real implementation, this would merge states and resolve conflicts
	merged := &MergedResult{
		State:     results[0].State,
		Conflicts: []StateConflict{},
		Resolution: ConflictResolution{
			Strategy: ResolutionStrategyPriority,
			Reason:   "Used first result",
		},
		Metadata: map[string]interface{}{
			"merged_results": len(results),
			"merge_strategy": "first_wins",
		},
	}

	return merged, nil
}
