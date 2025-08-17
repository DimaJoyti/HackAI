package education

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// EducationalPlatform provides comprehensive AI security training capabilities
type EducationalPlatform struct {
	logger             *logger.Logger
	courseManager      *CourseManager
	labManager         *LabManager
	assessmentEngine   *AssessmentEngine
	progressTracker    *ProgressTracker
	certificateManager *CertificateManager
	config             *PlatformConfig
	activeSessions     map[string]*LearningSession
	mu                 sync.RWMutex
}

// PlatformConfig configuration for the educational platform
type PlatformConfig struct {
	EnableInteractiveLabs  bool          `json:"enable_interactive_labs"`
	EnableAssessments      bool          `json:"enable_assessments"`
	EnableCertifications   bool          `json:"enable_certifications"`
	EnableProgressTracking bool          `json:"enable_progress_tracking"`
	MaxConcurrentSessions  int           `json:"max_concurrent_sessions"`
	SessionTimeout         time.Duration `json:"session_timeout"`
	EnableGamification     bool          `json:"enable_gamification"`
	EnableCollaboration    bool          `json:"enable_collaboration"`
	DefaultLanguage        string        `json:"default_language"`
	SupportedLanguages     []string      `json:"supported_languages"`
}

// LearningSession represents an active learning session
type LearningSession struct {
	ID           string                 `json:"id"`
	UserID       string                 `json:"user_id"`
	CourseID     string                 `json:"course_id"`
	ModuleID     string                 `json:"module_id"`
	Status       string                 `json:"status"`
	StartTime    time.Time              `json:"start_time"`
	LastActivity time.Time              `json:"last_activity"`
	Progress     *SessionProgress       `json:"progress"`
	CurrentLab   *LabSession            `json:"current_lab"`
	Achievements []*Achievement         `json:"achievements"`
	Notes        []string               `json:"notes"`
	Bookmarks    []string               `json:"bookmarks"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// SessionProgress tracks progress within a learning session
type SessionProgress struct {
	CompletedLessons   []string      `json:"completed_lessons"`
	CompletedLabs      []string      `json:"completed_labs"`
	CompletedQuizzes   []string      `json:"completed_quizzes"`
	CurrentLesson      string        `json:"current_lesson"`
	OverallProgress    float64       `json:"overall_progress"`
	TimeSpent          time.Duration `json:"time_spent"`
	LastCheckpoint     time.Time     `json:"last_checkpoint"`
	SkillsAcquired     []string      `json:"skills_acquired"`
	CompetenciesGained []string      `json:"competencies_gained"`
}

// Course represents a complete training course
type Course struct {
	ID                 string                 `json:"id"`
	Title              string                 `json:"title"`
	Description        string                 `json:"description"`
	Category           string                 `json:"category"`
	Level              string                 `json:"level"`
	Duration           time.Duration          `json:"duration"`
	Prerequisites      []string               `json:"prerequisites"`
	LearningObjectives []string               `json:"learning_objectives"`
	Modules            []*Module              `json:"modules"`
	Tags               []string               `json:"tags"`
	Language           string                 `json:"language"`
	Version            string                 `json:"version"`
	Author             string                 `json:"author"`
	CreatedAt          time.Time              `json:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at"`
	Metadata           map[string]interface{} `json:"metadata"`
}

// Module represents a course module
type Module struct {
	ID                 string                 `json:"id"`
	Title              string                 `json:"title"`
	Description        string                 `json:"description"`
	Order              int                    `json:"order"`
	EstimatedTime      time.Duration          `json:"estimated_time"`
	Lessons            []*Lesson              `json:"lessons"`
	Labs               []*Lab                 `json:"labs"`
	Assessments        []*Assessment          `json:"assessments"`
	Prerequisites      []string               `json:"prerequisites"`
	LearningObjectives []string               `json:"learning_objectives"`
	Metadata           map[string]interface{} `json:"metadata"`
}

// Lesson represents a learning lesson
type Lesson struct {
	ID                  string                 `json:"id"`
	Title               string                 `json:"title"`
	Description         string                 `json:"description"`
	Type                string                 `json:"type"`
	Content             *LessonContent         `json:"content"`
	Order               int                    `json:"order"`
	EstimatedTime       time.Duration          `json:"estimated_time"`
	Prerequisites       []string               `json:"prerequisites"`
	LearningObjectives  []string               `json:"learning_objectives"`
	InteractiveElements []*InteractiveElement  `json:"interactive_elements"`
	Resources           []*Resource            `json:"resources"`
	Metadata            map[string]interface{} `json:"metadata"`
}

// LessonContent represents the content of a lesson
type LessonContent struct {
	Text         string                 `json:"text"`
	HTML         string                 `json:"html"`
	Markdown     string                 `json:"markdown"`
	Videos       []*VideoContent        `json:"videos"`
	Images       []*ImageContent        `json:"images"`
	CodeExamples []*CodeExample         `json:"code_examples"`
	Diagrams     []*Diagram             `json:"diagrams"`
	Simulations  []*Simulation          `json:"simulations"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// VideoContent represents video content
type VideoContent struct {
	ID         string                 `json:"id"`
	Title      string                 `json:"title"`
	URL        string                 `json:"url"`
	Duration   time.Duration          `json:"duration"`
	Subtitles  map[string]string      `json:"subtitles"`
	Transcript string                 `json:"transcript"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// ImageContent represents image content
type ImageContent struct {
	ID       string                 `json:"id"`
	Title    string                 `json:"title"`
	URL      string                 `json:"url"`
	AltText  string                 `json:"alt_text"`
	Caption  string                 `json:"caption"`
	Metadata map[string]interface{} `json:"metadata"`
}

// CodeExample represents a code example
type CodeExample struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Language    string                 `json:"language"`
	Code        string                 `json:"code"`
	Explanation string                 `json:"explanation"`
	Runnable    bool                   `json:"runnable"`
	Expected    string                 `json:"expected"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Diagram represents a diagram or visualization
type Diagram struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Type        string                 `json:"type"`
	Content     string                 `json:"content"`
	Interactive bool                   `json:"interactive"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Simulation represents an interactive simulation
type Simulation struct {
	ID        string                 `json:"id"`
	Title     string                 `json:"title"`
	Type      string                 `json:"type"`
	Config    map[string]interface{} `json:"config"`
	Scenarios []*Scenario            `json:"scenarios"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// Scenario represents a simulation scenario
type Scenario struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
	Expected    map[string]interface{} `json:"expected"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// InteractiveElement represents an interactive element in a lesson
type InteractiveElement struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Title    string                 `json:"title"`
	Content  map[string]interface{} `json:"content"`
	Actions  []string               `json:"actions"`
	Feedback map[string]string      `json:"feedback"`
	Metadata map[string]interface{} `json:"metadata"`
}

// Resource represents a learning resource
type Resource struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Type        string                 `json:"type"`
	URL         string                 `json:"url"`
	Description string                 `json:"description"`
	Tags        []string               `json:"tags"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Lab represents a hands-on laboratory exercise
type Lab struct {
	ID            string                 `json:"id"`
	Title         string                 `json:"title"`
	Description   string                 `json:"description"`
	Type          string                 `json:"type"`
	Difficulty    string                 `json:"difficulty"`
	EstimatedTime time.Duration          `json:"estimated_time"`
	Environment   *LabEnvironment        `json:"environment"`
	Instructions  []*LabInstruction      `json:"instructions"`
	Objectives    []string               `json:"objectives"`
	Prerequisites []string               `json:"prerequisites"`
	Resources     []*Resource            `json:"resources"`
	Validation    *LabValidation         `json:"validation"`
	Hints         []string               `json:"hints"`
	Solutions     []*LabSolution         `json:"solutions"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// LabEnvironment represents a lab environment configuration
type LabEnvironment struct {
	ID             string                 `json:"id"`
	Type           string                 `json:"type"`
	Configuration  map[string]interface{} `json:"configuration"`
	Resources      map[string]interface{} `json:"resources"`
	NetworkConfig  map[string]interface{} `json:"network_config"`
	SecurityConfig map[string]interface{} `json:"security_config"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// LabInstruction represents a lab instruction step
type LabInstruction struct {
	ID          string                 `json:"id"`
	Step        int                    `json:"step"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Commands    []string               `json:"commands"`
	Expected    string                 `json:"expected"`
	Validation  map[string]interface{} `json:"validation"`
	Hints       []string               `json:"hints"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// LabValidation represents lab validation criteria
type LabValidation struct {
	Type      string                 `json:"type"`
	Criteria  []ValidationCriterion  `json:"criteria"`
	AutoCheck bool                   `json:"auto_check"`
	Timeout   time.Duration          `json:"timeout"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// ValidationCriterion represents a single validation criterion
type ValidationCriterion struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Type     string                 `json:"type"`
	Expected interface{}            `json:"expected"`
	Weight   float64                `json:"weight"`
	Required bool                   `json:"required"`
	Metadata map[string]interface{} `json:"metadata"`
}

// LabSolution represents a lab solution
type LabSolution struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Steps       []string               `json:"steps"`
	Code        map[string]string      `json:"code"`
	Explanation string                 `json:"explanation"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// LabSession represents an active lab session
type LabSession struct {
	ID          string                 `json:"id"`
	LabID       string                 `json:"lab_id"`
	UserID      string                 `json:"user_id"`
	Status      string                 `json:"status"`
	StartTime   time.Time              `json:"start_time"`
	EndTime     *time.Time             `json:"end_time"`
	Progress    *LabProgress           `json:"progress"`
	Environment *ActiveEnvironment     `json:"environment"`
	Submissions []*LabSubmission       `json:"submissions"`
	Feedback    []*LabFeedback         `json:"feedback"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// LabProgress tracks progress within a lab
type LabProgress struct {
	CompletedSteps  []int                  `json:"completed_steps"`
	CurrentStep     int                    `json:"current_step"`
	OverallProgress float64                `json:"overall_progress"`
	TimeSpent       time.Duration          `json:"time_spent"`
	Attempts        int                    `json:"attempts"`
	HintsUsed       []string               `json:"hints_used"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// ActiveEnvironment represents an active lab environment
type ActiveEnvironment struct {
	ID          string                 `json:"id"`
	Status      string                 `json:"status"`
	Endpoint    string                 `json:"endpoint"`
	Credentials map[string]string      `json:"credentials"`
	Resources   map[string]interface{} `json:"resources"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// LabSubmission represents a lab submission
type LabSubmission struct {
	ID          string                 `json:"id"`
	StepID      string                 `json:"step_id"`
	Content     map[string]interface{} `json:"content"`
	SubmittedAt time.Time              `json:"submitted_at"`
	Score       float64                `json:"score"`
	Feedback    string                 `json:"feedback"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// LabFeedback represents feedback for a lab
type LabFeedback struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Message   string                 `json:"message"`
	Severity  string                 `json:"severity"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// NewEducationalPlatform creates a new educational platform
func NewEducationalPlatform(config *PlatformConfig, logger *logger.Logger) *EducationalPlatform {
	if config == nil {
		config = DefaultPlatformConfig()
	}

	platform := &EducationalPlatform{
		logger:         logger,
		config:         config,
		activeSessions: make(map[string]*LearningSession),
	}

	// Initialize components
	platform.courseManager = NewCourseManager(logger)
	platform.labManager = NewLabManager(logger)
	platform.assessmentEngine = NewAssessmentEngine(logger)
	platform.progressTracker = NewProgressTracker(logger)
	platform.certificateManager = NewCertificateManager(logger)

	return platform
}

// DefaultPlatformConfig returns default platform configuration
func DefaultPlatformConfig() *PlatformConfig {
	return &PlatformConfig{
		EnableInteractiveLabs:  true,
		EnableAssessments:      true,
		EnableCertifications:   true,
		EnableProgressTracking: true,
		MaxConcurrentSessions:  100,
		SessionTimeout:         4 * time.Hour,
		EnableGamification:     true,
		EnableCollaboration:    true,
		DefaultLanguage:        "en",
		SupportedLanguages:     []string{"en", "es", "fr", "de", "zh", "ja"},
	}
}

// StartLearningSession starts a new learning session
func (ep *EducationalPlatform) StartLearningSession(ctx context.Context, userID, courseID string) (*LearningSession, error) {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	// Check concurrent session limit
	if len(ep.activeSessions) >= ep.config.MaxConcurrentSessions {
		return nil, fmt.Errorf("maximum concurrent sessions limit reached")
	}

	// Get course
	course, err := ep.courseManager.GetCourse(ctx, courseID)
	if err != nil {
		return nil, fmt.Errorf("failed to get course: %w", err)
	}

	// Get user progress to ensure user exists
	_, err = ep.progressTracker.GetUserProgress(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user progress: %w", err)
	}

	session := &LearningSession{
		ID:           uuid.New().String(),
		UserID:       userID,
		CourseID:     courseID,
		Status:       "active",
		StartTime:    time.Now(),
		LastActivity: time.Now(),
		Progress: &SessionProgress{
			CompletedLessons:   []string{},
			CompletedLabs:      []string{},
			CompletedQuizzes:   []string{},
			CurrentLesson:      "",
			OverallProgress:    0.0,
			TimeSpent:          0,
			LastCheckpoint:     time.Now(),
			SkillsAcquired:     []string{},
			CompetenciesGained: []string{},
		},
		Achievements: []*Achievement{},
		Notes:        []string{},
		Bookmarks:    []string{},
		Metadata:     make(map[string]interface{}),
	}

	// Set current lesson to first lesson of first module
	if len(course.Modules) > 0 && len(course.Modules[0].Lessons) > 0 {
		session.Progress.CurrentLesson = course.Modules[0].Lessons[0].ID
	}

	ep.activeSessions[session.ID] = session

	// Start session timeout
	go ep.handleSessionTimeout(session.ID)

	ep.logger.WithFields(map[string]interface{}{
		"session_id": session.ID,
		"user_id":    userID,
		"course_id":  courseID,
	}).Info("Learning session started")

	return session, nil
}

// handleSessionTimeout handles session timeout
func (ep *EducationalPlatform) handleSessionTimeout(sessionID string) {
	time.Sleep(ep.config.SessionTimeout)

	ep.mu.Lock()
	defer ep.mu.Unlock()

	if session, exists := ep.activeSessions[sessionID]; exists {
		if session.Status == "active" {
			session.Status = "timeout"
			ep.logger.WithField("session_id", sessionID).Info("Learning session timed out")
		}
	}
}

// CompleteLesson marks a lesson as completed
func (ep *EducationalPlatform) CompleteLesson(sessionID, lessonID string, timeSpent time.Duration) error {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	session, exists := ep.activeSessions[sessionID]
	if !exists {
		return fmt.Errorf("learning session not found: %s", sessionID)
	}

	// Update session progress
	session.Progress.CompletedLessons = append(session.Progress.CompletedLessons, lessonID)
	session.Progress.TimeSpent += timeSpent
	session.LastActivity = time.Now()

	// Update user progress
	activity := &LearningActivity{
		ID:           uuid.New().String(),
		UserID:       session.UserID,
		CourseID:     session.CourseID,
		ModuleID:     "", // Would be determined from lesson
		ActivityType: "lesson_completed",
		Duration:     timeSpent,
		Completed:    true,
		Timestamp:    time.Now(),
		Metadata:     make(map[string]interface{}),
	}

	err := ep.progressTracker.TrackActivity(context.Background(), activity)
	if err != nil {
		ep.logger.WithError(err).Error("Failed to update user progress")
	}

	ep.logger.WithFields(map[string]interface{}{
		"session_id": sessionID,
		"lesson_id":  lessonID,
		"time_spent": timeSpent,
	}).Info("Lesson completed")

	return nil
}

// StartLab starts a lab session
func (ep *EducationalPlatform) StartLab(ctx context.Context, sessionID, labID string) (*LabSession, error) {
	ep.mu.Lock()
	session, exists := ep.activeSessions[sessionID]
	ep.mu.Unlock()

	if !exists {
		return nil, fmt.Errorf("learning session not found: %s", sessionID)
	}

	// Start lab session
	labSession, err := ep.labManager.StartLabSession(ctx, labID, session.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to start lab session: %w", err)
	}

	// Update learning session
	ep.mu.Lock()
	session.CurrentLab = labSession
	session.LastActivity = time.Now()
	ep.mu.Unlock()

	return labSession, nil
}

// StartAssessment starts an assessment
func (ep *EducationalPlatform) StartAssessment(ctx context.Context, sessionID, assessmentID string) (*AssessmentAttempt, error) {
	ep.mu.Lock()
	session, exists := ep.activeSessions[sessionID]
	ep.mu.Unlock()

	if !exists {
		return nil, fmt.Errorf("learning session not found: %s", sessionID)
	}

	// Start assessment attempt
	attempt, err := ep.assessmentEngine.StartAssessment(ctx, assessmentID, session.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to start assessment: %w", err)
	}

	// Update learning session
	ep.mu.Lock()
	session.LastActivity = time.Now()
	ep.mu.Unlock()

	return attempt, nil
}

// CompleteCourse marks a course as completed and issues certificate if eligible
func (ep *EducationalPlatform) CompleteCourse(sessionID, courseID string, finalScore float64) (*Certificate, error) {
	ep.mu.Lock()
	session, exists := ep.activeSessions[sessionID]
	ep.mu.Unlock()

	if !exists {
		return nil, fmt.Errorf("learning session not found: %s", sessionID)
	}

	// Update user progress
	finalScorePtr := &finalScore
	activity := &LearningActivity{
		ID:           uuid.New().String(),
		UserID:       session.UserID,
		CourseID:     courseID,
		ModuleID:     "", // Course completion spans all modules
		ActivityType: "course_completed",
		Duration:     0, // Course completion doesn't have duration
		Score:        finalScorePtr,
		Completed:    true,
		Timestamp:    time.Now(),
		Metadata:     make(map[string]interface{}),
	}

	err := ep.progressTracker.TrackActivity(context.Background(), activity)
	if err != nil {
		ep.logger.WithError(err).Error("Failed to update user progress")
	}

	// Issue certificate if eligible
	var certificate *Certificate
	if ep.config.EnableCertifications && finalScore >= 70.0 {
		certificate, err = ep.certificateManager.IssueCertificate(
			context.Background(),
			"course-completion",
			session.UserID,
			courseID,
			finalScore,
		)
		if err != nil {
			ep.logger.WithError(err).Error("Failed to issue certificate")
		}
	}

	ep.logger.WithFields(map[string]interface{}{
		"session_id":         sessionID,
		"course_id":          courseID,
		"final_score":        finalScore,
		"certificate_issued": certificate != nil,
	}).Info("Course completed")

	return certificate, nil
}

// GetLearningRecommendations gets personalized learning recommendations
func (ep *EducationalPlatform) GetLearningRecommendations(userID string) ([]*LearningRecommendation, error) {
	return ep.progressTracker.GetRecommendations(context.Background(), userID)
}

// GetUserDashboard gets user dashboard data
func (ep *EducationalPlatform) GetUserDashboard(userID string) (*UserDashboard, error) {
	// Get user progress
	progress, err := ep.progressTracker.GetUserProgress(context.Background(), userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user progress: %w", err)
	}

	// Get user certificates
	certificates, err := ep.certificateManager.GetUserCertificates(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user certificates: %w", err)
	}

	// Get recommendations
	recommendations, err := ep.progressTracker.GetRecommendations(context.Background(), userID)
	if err != nil {
		ep.logger.WithError(err).Warn("Failed to get recommendations")
		recommendations = []*LearningRecommendation{}
	}

	dashboard := &UserDashboard{
		UserID:            userID,
		Progress:          progress,
		Certificates:      certificates,
		Recommendations:   recommendations,
		RecentActivity:    ep.getRecentActivity(userID),
		UpcomingDeadlines: ep.getUpcomingDeadlines(userID),
		Metadata:          make(map[string]interface{}),
		LastUpdated:       time.Now(),
	}

	return dashboard, nil
}

// UserDashboard represents user dashboard data
type UserDashboard struct {
	UserID            string                    `json:"user_id"`
	Progress          *UserProgress             `json:"progress"`
	Certificates      []*Certificate            `json:"certificates"`
	Recommendations   []*LearningRecommendation `json:"recommendations"`
	RecentActivity    []*ActivityItem           `json:"recent_activity"`
	UpcomingDeadlines []*DeadlineItem           `json:"upcoming_deadlines"`
	Metadata          map[string]interface{}    `json:"metadata"`
	LastUpdated       time.Time                 `json:"last_updated"`
}

// ActivityItem represents a recent activity item
type ActivityItem struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// DeadlineItem represents an upcoming deadline
type DeadlineItem struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	DueDate     time.Time              `json:"due_date"`
	Priority    string                 `json:"priority"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// getRecentActivity gets recent activity for user (simplified)
func (ep *EducationalPlatform) getRecentActivity(userID string) []*ActivityItem {
	// In a real implementation, this would query activity logs
	return []*ActivityItem{
		{
			ID:          uuid.New().String(),
			Type:        "lesson_completed",
			Title:       "Completed AI Threat Landscape",
			Description: "Finished lesson on AI security threats",
			Timestamp:   time.Now().Add(-2 * time.Hour),
			Metadata:    make(map[string]interface{}),
		},
		{
			ID:          uuid.New().String(),
			Type:        "lab_started",
			Title:       "Started Prompt Injection Lab",
			Description: "Began hands-on prompt injection testing",
			Timestamp:   time.Now().Add(-1 * time.Hour),
			Metadata:    make(map[string]interface{}),
		},
	}
}

// getUpcomingDeadlines gets upcoming deadlines for user (simplified)
func (ep *EducationalPlatform) getUpcomingDeadlines(userID string) []*DeadlineItem {
	// In a real implementation, this would query user's goals and course deadlines
	return []*DeadlineItem{
		{
			ID:          uuid.New().String(),
			Type:        "assessment",
			Title:       "AI Security Fundamentals Quiz",
			Description: "Complete the fundamentals assessment",
			DueDate:     time.Now().Add(3 * 24 * time.Hour),
			Priority:    "high",
			Metadata:    make(map[string]interface{}),
		},
	}
}
