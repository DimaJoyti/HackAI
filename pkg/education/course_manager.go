package education

import (
	"context"
	"fmt"
	"sync"

	"github.com/dimajoyti/hackai/pkg/logger"
)

// CourseManager manages educational courses and content
type CourseManager struct {
	logger  *logger.Logger
	courses map[string]*Course
	mu      sync.RWMutex
}

// NewCourseManager creates a new course manager
func NewCourseManager(logger *logger.Logger) *CourseManager {
	manager := &CourseManager{
		logger:  logger,
		courses: make(map[string]*Course),
	}

	logger.Info("Course manager initialized")
	return manager
}

// GetCourse retrieves a course by ID
func (cm *CourseManager) GetCourse(ctx context.Context, courseID string) (*Course, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	course, exists := cm.courses[courseID]
	if !exists {
		return nil, fmt.Errorf("course not found: %s", courseID)
	}

	return course, nil
}

// AddCourse adds a course to the manager
func (cm *CourseManager) AddCourse(ctx context.Context, course *Course) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.courses[course.ID] = course
	cm.logger.Info("Course added", "course_id", course.ID, "title", course.Title)
	return nil
}

// ListCourses lists all courses
func (cm *CourseManager) ListCourses(ctx context.Context) ([]*Course, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	var courses []*Course
	for _, course := range cm.courses {
		courses = append(courses, course)
	}

	return courses, nil
}
