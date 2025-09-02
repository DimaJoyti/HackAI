package education

import (
	"context"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// ProgressTracker manages user learning progress and analytics
type ProgressTracker struct {
	logger       *logger.Logger
	userProgress map[string]*UserProgress
	activities   map[string]*LearningActivity
	config       *ProgressConfig
	mu           sync.RWMutex
}

// ProgressConfig configuration for progress tracking
type ProgressConfig struct {
	EnableDetailedTracking bool          `json:"enable_detailed_tracking"`
	EnableAnalytics        bool          `json:"enable_analytics"`
	EnableRecommendations  bool          `json:"enable_recommendations"`
	TrackingGranularity    string        `json:"tracking_granularity"` // "course", "module", "activity"
	AnalyticsRetention     time.Duration `json:"analytics_retention"`
}

// UserProgress represents a user's learning progress
type UserProgress struct {
	UserID           string                     `json:"user_id"`
	CourseProgress   map[string]*CourseProgress `json:"course_progress"`
	TotalTimeSpent   time.Duration              `json:"total_time_spent"`
	CompletedCourses int                        `json:"completed_courses"`
	TotalScore       float64                    `json:"total_score"`
	Achievements     []string                   `json:"achievements"`
	LastActive       time.Time                  `json:"last_active"`
	CreatedAt        time.Time                  `json:"created_at"`
	UpdatedAt        time.Time                  `json:"updated_at"`
}

// CourseProgress represents progress in a specific course
type CourseProgress struct {
	CourseID       string             `json:"course_id"`
	ModuleProgress map[string]float64 `json:"module_progress"`
	CompletionRate float64            `json:"completion_rate"`
	TimeSpent      time.Duration      `json:"time_spent"`
	Score          float64            `json:"score"`
	Status         string             `json:"status"` // "not_started", "in_progress", "completed"
	StartedAt      time.Time          `json:"started_at"`
	CompletedAt    *time.Time         `json:"completed_at,omitempty"`
}

// LearningActivity represents a learning activity
type LearningActivity struct {
	ID           string                 `json:"id"`
	UserID       string                 `json:"user_id"`
	CourseID     string                 `json:"course_id"`
	ModuleID     string                 `json:"module_id"`
	ActivityType string                 `json:"activity_type"` // "video", "quiz", "lab", "assignment"
	Duration     time.Duration          `json:"duration"`
	Score        *float64               `json:"score,omitempty"`
	Completed    bool                   `json:"completed"`
	Metadata     map[string]interface{} `json:"metadata"`
	Timestamp    time.Time              `json:"timestamp"`
}

// LearningRecommendation represents a personalized learning recommendation
type LearningRecommendation struct {
	ID          string                 `json:"id"`
	UserID      string                 `json:"user_id"`
	Type        string                 `json:"type"` // "course", "module", "skill"
	ContentID   string                 `json:"content_id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Reason      string                 `json:"reason"`
	Confidence  float64                `json:"confidence"`
	Priority    int                    `json:"priority"`
	Metadata    map[string]interface{} `json:"metadata"`
	GeneratedAt time.Time              `json:"generated_at"`
	ExpiresAt   time.Time              `json:"expires_at"`
}

// NewProgressTracker creates a new progress tracker
func NewProgressTracker(logger *logger.Logger) *ProgressTracker {
	tracker := &ProgressTracker{
		logger:       logger,
		userProgress: make(map[string]*UserProgress),
		activities:   make(map[string]*LearningActivity),
		config: &ProgressConfig{
			EnableDetailedTracking: true,
			EnableAnalytics:        true,
			EnableRecommendations:  true,
			TrackingGranularity:    "activity",
			AnalyticsRetention:     90 * 24 * time.Hour, // 90 days
		},
	}

	logger.Info("Progress tracker initialized")
	return tracker
}

// TrackActivity records a learning activity
func (pt *ProgressTracker) TrackActivity(ctx context.Context, activity *LearningActivity) error {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	// Generate ID if not provided
	if activity.ID == "" {
		activity.ID = uuid.New().String()
	}

	// Set timestamp if not provided
	if activity.Timestamp.IsZero() {
		activity.Timestamp = time.Now()
	}

	// Store activity
	pt.activities[activity.ID] = activity

	// Update user progress
	if err := pt.updateUserProgress(activity); err != nil {
		pt.logger.Error("Failed to update user progress", "error", err, "activity_id", activity.ID)
		return err
	}

	pt.logger.Info("Learning activity tracked",
		"activity_id", activity.ID,
		"user_id", activity.UserID,
		"course_id", activity.CourseID,
		"type", activity.ActivityType)

	return nil
}

// GetUserProgress retrieves user progress
func (pt *ProgressTracker) GetUserProgress(ctx context.Context, userID string) (*UserProgress, error) {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	progress, exists := pt.userProgress[userID]
	if !exists {
		// Create new progress record
		progress = &UserProgress{
			UserID:         userID,
			CourseProgress: make(map[string]*CourseProgress),
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}
		pt.userProgress[userID] = progress
	}

	return progress, nil
}

// GetRecommendations generates learning recommendations for a user
func (pt *ProgressTracker) GetRecommendations(ctx context.Context, userID string) ([]*LearningRecommendation, error) {
	if !pt.config.EnableRecommendations {
		return []*LearningRecommendation{}, nil
	}

	pt.mu.RLock()
	defer pt.mu.RUnlock()

	progress, exists := pt.userProgress[userID]
	if !exists {
		return []*LearningRecommendation{}, nil
	}

	var recommendations []*LearningRecommendation

	// Generate basic recommendations based on progress
	for courseID, courseProgress := range progress.CourseProgress {
		if courseProgress.Status == "in_progress" && courseProgress.CompletionRate < 0.8 {
			recommendation := &LearningRecommendation{
				ID:          uuid.New().String(),
				UserID:      userID,
				Type:        "course",
				ContentID:   courseID,
				Title:       "Continue Course Progress",
				Description: "Complete your current course to unlock new content",
				Reason:      "Course in progress with good momentum",
				Confidence:  0.8,
				Priority:    1,
				GeneratedAt: time.Now(),
				ExpiresAt:   time.Now().Add(7 * 24 * time.Hour),
			}
			recommendations = append(recommendations, recommendation)
		}
	}

	pt.logger.Info("Generated recommendations",
		"user_id", userID,
		"count", len(recommendations))

	return recommendations, nil
}

// updateUserProgress updates user progress based on activity
func (pt *ProgressTracker) updateUserProgress(activity *LearningActivity) error {
	progress, exists := pt.userProgress[activity.UserID]
	if !exists {
		progress = &UserProgress{
			UserID:         activity.UserID,
			CourseProgress: make(map[string]*CourseProgress),
			CreatedAt:      time.Now(),
		}
		pt.userProgress[activity.UserID] = progress
	}

	// Update course progress
	courseProgress, exists := progress.CourseProgress[activity.CourseID]
	if !exists {
		courseProgress = &CourseProgress{
			CourseID:       activity.CourseID,
			ModuleProgress: make(map[string]float64),
			Status:         "in_progress",
			StartedAt:      time.Now(),
		}
		progress.CourseProgress[activity.CourseID] = courseProgress
	}

	// Update time spent
	progress.TotalTimeSpent += activity.Duration
	courseProgress.TimeSpent += activity.Duration

	// Update scores if provided
	if activity.Score != nil {
		courseProgress.Score = *activity.Score
		progress.TotalScore += *activity.Score
	}

	// Mark completion if activity is completed
	if activity.Completed {
		courseProgress.ModuleProgress[activity.ModuleID] = 1.0
		// Recalculate completion rate
		courseProgress.CompletionRate = pt.calculateCompletionRate(courseProgress)

		if courseProgress.CompletionRate >= 1.0 {
			courseProgress.Status = "completed"
			now := time.Now()
			courseProgress.CompletedAt = &now
			progress.CompletedCourses++
		}
	}

	progress.LastActive = time.Now()
	progress.UpdatedAt = time.Now()

	return nil
}

// calculateCompletionRate calculates course completion rate
func (pt *ProgressTracker) calculateCompletionRate(courseProgress *CourseProgress) float64 {
	if len(courseProgress.ModuleProgress) == 0 {
		return 0.0
	}

	var total float64
	for _, progress := range courseProgress.ModuleProgress {
		total += progress
	}

	return total / float64(len(courseProgress.ModuleProgress))
}

// EnrollUser enrolls a user in a course
func (pt *ProgressTracker) EnrollUser(ctx context.Context, userID, courseID string) error {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	// Get or create user progress
	progress, exists := pt.userProgress[userID]
	if !exists {
		progress = &UserProgress{
			UserID:         userID,
			CourseProgress: make(map[string]*CourseProgress),
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}
		pt.userProgress[userID] = progress
	}

	// Check if already enrolled
	if _, enrolled := progress.CourseProgress[courseID]; enrolled {
		return nil // Already enrolled
	}

	// Create course progress entry
	courseProgress := &CourseProgress{
		CourseID:       courseID,
		ModuleProgress: make(map[string]float64),
		CompletionRate: 0.0,
		TimeSpent:      0,
		Score:          0.0,
		Status:         "not_started",
		StartedAt:      time.Now(),
	}

	progress.CourseProgress[courseID] = courseProgress
	progress.UpdatedAt = time.Now()

	pt.logger.Info("User enrolled in course",
		"user_id", userID,
		"course_id", courseID)

	return nil
}
