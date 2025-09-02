package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/dimajoyti/hackai/pkg/education"
	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/gorilla/mux"
)

// EducationHandler handles education-related HTTP requests
type EducationHandler struct {
	platform *education.EducationalPlatform
	logger   *logger.Logger
}

// NewEducationHandler creates a new education handler
func NewEducationHandler(platform *education.EducationalPlatform, logger *logger.Logger) *EducationHandler {
	return &EducationHandler{
		platform: platform,
		logger:   logger,
	}
}

// RegisterRoutes registers education routes
func (h *EducationHandler) RegisterRoutes(router *mux.Router) {
	// Course management
	router.HandleFunc("/api/education/courses", h.ListCourses).Methods("GET")
	router.HandleFunc("/api/education/courses/{id}", h.GetCourse).Methods("GET")
	router.HandleFunc("/api/education/courses/{id}/enroll", h.EnrollCourse).Methods("POST")
	router.HandleFunc("/api/education/courses/{id}/modules", h.GetCourseModules).Methods("GET")
	router.HandleFunc("/api/education/courses/{courseId}/modules/{moduleId}", h.GetModule).Methods("GET")

	// Learning sessions
	router.HandleFunc("/api/education/sessions", h.StartLearningSession).Methods("POST")
	router.HandleFunc("/api/education/sessions/{id}", h.GetLearningSession).Methods("GET")
	router.HandleFunc("/api/education/sessions/{id}/progress", h.UpdateSessionProgress).Methods("PUT")
	router.HandleFunc("/api/education/sessions/{id}/complete", h.CompleteLearningSession).Methods("POST")

	// Lab management
	router.HandleFunc("/api/education/labs", h.ListLabs).Methods("GET")
	router.HandleFunc("/api/education/labs/{id}", h.GetLab).Methods("GET")
	router.HandleFunc("/api/education/labs/{id}/start", h.StartLab).Methods("POST")
	router.HandleFunc("/api/education/labs/sessions/{sessionId}", h.GetLabSession).Methods("GET")
	router.HandleFunc("/api/education/labs/sessions/{sessionId}/submit", h.SubmitLabWork).Methods("POST")
	router.HandleFunc("/api/education/labs/sessions/{sessionId}/complete", h.CompleteLab).Methods("POST")

	// Assessment management
	router.HandleFunc("/api/education/assessments", h.ListAssessments).Methods("GET")
	router.HandleFunc("/api/education/assessments/{id}", h.GetAssessment).Methods("GET")
	router.HandleFunc("/api/education/assessments/{id}/start", h.StartAssessment).Methods("POST")
	router.HandleFunc("/api/education/assessments/attempts/{attemptId}", h.GetAssessmentAttempt).Methods("GET")
	router.HandleFunc("/api/education/assessments/attempts/{attemptId}/submit", h.SubmitAssessmentResponse).Methods("POST")
	router.HandleFunc("/api/education/assessments/attempts/{attemptId}/complete", h.CompleteAssessment).Methods("POST")

	// Progress tracking
	router.HandleFunc("/api/education/progress/{userId}", h.GetUserProgress).Methods("GET")
	router.HandleFunc("/api/education/progress/{userId}/achievements", h.GetUserAchievements).Methods("GET")
	router.HandleFunc("/api/education/progress/{userId}/certificates", h.GetUserCertificates).Methods("GET")
	router.HandleFunc("/api/education/progress/{userId}/recommendations", h.GetRecommendations).Methods("GET")

	// Dashboard
	router.HandleFunc("/api/education/dashboard/{userId}", h.GetUserDashboard).Methods("GET")
	router.HandleFunc("/api/education/analytics/{userId}", h.GetUserAnalytics).Methods("GET")
}

// ListCourses handles GET /api/education/courses
func (h *EducationHandler) ListCourses(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	category := r.URL.Query().Get("category")
	level := r.URL.Query().Get("level")
	search := r.URL.Query().Get("search")

	limitStr := r.URL.Query().Get("limit")
	limit := 20 // default
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	offsetStr := r.URL.Query().Get("offset")
	offset := 0 // default
	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	// Get courses from platform
	courses, err := h.platform.ListCourses(ctx, education.CourseFilter{
		Category:    category,
		Level:       level,
		SearchQuery: search,
	})
	if err != nil {
		h.logger.WithError(err).Error("Failed to list courses")
		http.Error(w, "Failed to retrieve courses", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"courses": courses,
		"total":   len(courses),
		"limit":   limit,
		"offset":  offset,
	})
}

// GetCourse handles GET /api/education/courses/{id}
func (h *EducationHandler) GetCourse(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	courseID := vars["id"]

	course, err := h.platform.GetCourse(ctx, courseID)
	if err != nil {
		h.logger.WithError(err).WithField("course_id", courseID).Error("Failed to get course")
		http.Error(w, "Course not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(course)
}

// EnrollCourse handles POST /api/education/courses/{id}/enroll
func (h *EducationHandler) EnrollCourse(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	courseID := vars["id"]

	// Get user ID from context (set by auth middleware)
	userID, ok := ctx.Value("user_id").(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	err := h.platform.EnrollUser(ctx, userID, courseID)
	if err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"user_id":   userID,
			"course_id": courseID,
		}).Error("Failed to enroll user in course")
		http.Error(w, "Failed to enroll in course", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   "Successfully enrolled in course",
		"user_id":   userID,
		"course_id": courseID,
	})
}

// StartLearningSession handles POST /api/education/sessions
func (h *EducationHandler) StartLearningSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user ID from context
	userID, ok := ctx.Value("user_id").(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		CourseID string `json:"course_id"`
		ModuleID string `json:"module_id,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	session, err := h.platform.StartLearningSession(ctx, userID, req.CourseID)
	if err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"user_id":   userID,
			"course_id": req.CourseID,
		}).Error("Failed to start learning session")
		http.Error(w, "Failed to start learning session", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(session)
}

// GetLearningSession handles GET /api/education/sessions/{id}
func (h *EducationHandler) GetLearningSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	sessionID := vars["id"]

	session, err := h.platform.GetLearningSession(ctx, sessionID)
	if err != nil {
		h.logger.WithError(err).WithField("session_id", sessionID).Error("Failed to get learning session")
		http.Error(w, "Learning session not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session)
}

// StartLab handles POST /api/education/labs/{id}/start
func (h *EducationHandler) StartLab(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	labID := vars["id"]

	// Get user ID from context
	userID, ok := ctx.Value("user_id").(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	labSession, err := h.platform.StartLab(ctx, labID, userID)
	if err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"user_id": userID,
			"lab_id":  labID,
		}).Error("Failed to start lab")
		http.Error(w, "Failed to start lab", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(labSession)
}

// StartAssessment handles POST /api/education/assessments/{id}/start
func (h *EducationHandler) StartAssessment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	assessmentID := vars["id"]

	// Get user ID from context
	userID, ok := ctx.Value("user_id").(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		SessionID string `json:"session_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	attempt, err := h.platform.StartAssessment(ctx, req.SessionID, assessmentID)
	if err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"user_id":       userID,
			"assessment_id": assessmentID,
			"session_id":    req.SessionID,
		}).Error("Failed to start assessment")
		http.Error(w, "Failed to start assessment", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(attempt)
}

// GetUserDashboard handles GET /api/education/dashboard/{userId}
func (h *EducationHandler) GetUserDashboard(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["userId"]

	// Verify user access (user can only access their own dashboard or admin access)
	ctxUserID, ok := r.Context().Value("user_id").(string)
	if !ok || (ctxUserID != userID && !h.isAdmin(r.Context())) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	dashboard, err := h.platform.GetUserDashboard(userID)
	if err != nil {
		h.logger.WithError(err).WithField("user_id", userID).Error("Failed to get user dashboard")
		http.Error(w, "Failed to retrieve dashboard", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dashboard)
}

// UpdateSessionProgress handles PUT /api/education/sessions/{id}/progress
func (h *EducationHandler) UpdateSessionProgress(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	sessionID := vars["id"]

	var progress education.SessionProgress
	if err := json.NewDecoder(r.Body).Decode(&progress); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err := h.platform.UpdateSessionProgress(ctx, sessionID, &progress)
	if err != nil {
		h.logger.WithError(err).WithField("session_id", sessionID).Error("Failed to update session progress")
		http.Error(w, "Failed to update progress", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetCourseModules handles GET /api/education/courses/{id}/modules
func (h *EducationHandler) GetCourseModules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	courseID := vars["id"]

	// Validate courseID
	if courseID == "" {
		h.logger.Error("Course ID is required")
		http.Error(w, "Course ID is required", http.StatusBadRequest)
		return
	}

	modules, err := h.platform.GetCourseModules(ctx, courseID)
	if err != nil {
		h.logger.WithError(err).WithField("course_id", courseID).Error("Failed to get course modules")
		
		// Handle specific error types
		if strings.Contains(err.Error(), "not found") {
			http.Error(w, "Course not found", http.StatusNotFound)
			return
		}
		
		http.Error(w, "Failed to retrieve modules", http.StatusInternalServerError)
		return
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Encode response with error handling
	response := map[string]any{
		"modules": modules,
		"total":   len(modules),
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.WithError(err).Error("Failed to encode response")
		// At this point headers are already written, so we can't change the status code
		// Just log the error for monitoring
	}
}

// GetModule handles GET /api/education/courses/{courseId}/modules/{moduleId}
func (h *EducationHandler) GetModule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	moduleID := vars["moduleId"]

	module, err := h.platform.GetModule(ctx, moduleID)
	if err != nil {
		h.logger.WithError(err).WithField("module_id", moduleID).Error("Failed to get module")
		http.Error(w, "Module not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(module)
}

// ListLabs handles GET /api/education/labs
func (h *EducationHandler) ListLabs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	difficulty := r.URL.Query().Get("difficulty")
	labType := r.URL.Query().Get("type")

	labs, err := h.platform.ListLabs(ctx, education.LabFilter{
		Difficulty: difficulty,
		Type:       labType,
	})
	if err != nil {
		h.logger.WithError(err).Error("Failed to list labs")
		http.Error(w, "Failed to retrieve labs", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"labs":  labs,
		"total": len(labs),
	})
}

// GetLab handles GET /api/education/labs/{id}
func (h *EducationHandler) GetLab(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	labID := vars["id"]

	lab, err := h.platform.GetLab(ctx, labID)
	if err != nil {
		h.logger.WithError(err).WithField("lab_id", labID).Error("Failed to get lab")
		http.Error(w, "Lab not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(lab)
}

// GetLabSession handles GET /api/education/labs/sessions/{sessionId}
func (h *EducationHandler) GetLabSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	sessionID := vars["sessionId"]

	session, err := h.platform.GetLabSession(ctx, sessionID)
	if err != nil {
		h.logger.WithError(err).WithField("session_id", sessionID).Error("Failed to get lab session")
		http.Error(w, "Lab session not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session)
}

// SubmitLabWork handles POST /api/education/labs/sessions/{sessionId}/submit
func (h *EducationHandler) SubmitLabWork(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	sessionID := vars["sessionId"]

	var submission struct {
		StepID   string                 `json:"step_id"`
		Content  map[string]interface{} `json:"content"`
		Comments string                 `json:"comments"`
	}

	if err := json.NewDecoder(r.Body).Decode(&submission); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Add comments to content if provided
	if submission.Comments != "" {
		if submission.Content == nil {
			submission.Content = make(map[string]interface{})
		}
		submission.Content["comments"] = submission.Comments
	}

	result, err := h.platform.SubmitLabWork(ctx, sessionID, submission.StepID, submission.Content)
	if err != nil {
		h.logger.WithError(err).WithField("session_id", sessionID).Error("Failed to submit lab work")
		http.Error(w, "Failed to submit lab work", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// CompleteLab handles POST /api/education/labs/sessions/{sessionId}/complete
func (h *EducationHandler) CompleteLab(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	sessionID := vars["sessionId"]

	err := h.platform.CompleteLab(ctx, sessionID)
	if err != nil {
		h.logger.WithError(err).WithField("session_id", sessionID).Error("Failed to complete lab")
		http.Error(w, "Failed to complete lab", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":    "Lab completed successfully",
		"session_id": sessionID,
	})
}

// CompleteLearningSession handles POST /api/education/sessions/{id}/complete
func (h *EducationHandler) CompleteLearningSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	sessionID := vars["id"]

	err := h.platform.CompleteLearningSession(ctx, sessionID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to complete learning session")
		http.Error(w, "Failed to complete session", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListAssessments handles GET /api/education/assessments
func (h *EducationHandler) ListAssessments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	assessmentType := r.URL.Query().Get("type")
	difficulty := r.URL.Query().Get("difficulty")
	category := r.URL.Query().Get("category")

	search := r.URL.Query().Get("search")

	filter := education.AssessmentFilter{
		Type:        assessmentType,
		Difficulty:  difficulty,
		Category:    category,
		SearchQuery: search,
	}

	assessments, err := h.platform.ListAssessments(ctx, filter)
	if err != nil {
		h.logger.WithError(err).Error("Failed to list assessments")
		http.Error(w, "Failed to list assessments", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"assessments": assessments,
		"total":       len(assessments),
	})
}

// GetAssessment handles GET /api/education/assessments/{id}
func (h *EducationHandler) GetAssessment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	assessmentID := vars["id"]

	assessment, err := h.platform.GetAssessment(ctx, assessmentID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get assessment")
		http.Error(w, "Assessment not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(assessment)
}

// GetAssessmentAttempt handles GET /api/education/assessments/attempts/{attemptId}
func (h *EducationHandler) GetAssessmentAttempt(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	attemptID := vars["attemptId"]

	attempt, err := h.platform.GetAssessmentAttempt(ctx, attemptID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get assessment attempt")
		http.Error(w, "Assessment attempt not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(attempt)
}

// SubmitAssessmentResponse handles POST /api/education/assessments/attempts/{attemptId}/submit
func (h *EducationHandler) SubmitAssessmentResponse(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	attemptID := vars["attemptId"]

	var requestData struct {
		QuestionID string      `json:"question_id"`
		Answer     interface{} `json:"answer"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Create responses map
	responses := map[string]interface{}{
		requestData.QuestionID: requestData.Answer,
	}

	result, err := h.platform.SubmitAssessmentResponse(ctx, attemptID, responses)
	if err != nil {
		h.logger.WithError(err).Error("Failed to submit assessment response")
		http.Error(w, "Failed to submit response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// CompleteAssessment handles POST /api/education/assessments/attempts/{attemptId}/complete
func (h *EducationHandler) CompleteAssessment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	attemptID := vars["attemptId"]

	result, err := h.platform.CompleteAssessment(ctx, attemptID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to complete assessment")
		http.Error(w, "Failed to complete assessment", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// GetUserProgress handles GET /api/education/progress/{userId}
func (h *EducationHandler) GetUserProgress(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userID := vars["userId"]

	progress, err := h.platform.GetUserProgress(ctx, userID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get user progress")
		http.Error(w, "Failed to get progress", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(progress)
}

// GetUserAchievements handles GET /api/education/progress/{userId}/achievements
func (h *EducationHandler) GetUserAchievements(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userID := vars["userId"]

	achievements, err := h.platform.GetUserAchievements(ctx, userID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get user achievements")
		http.Error(w, "Failed to get achievements", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"achievements": achievements,
		"total":        len(achievements),
	})
}

// GetUserCertificates handles GET /api/education/progress/{userId}/certificates
func (h *EducationHandler) GetUserCertificates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userID := vars["userId"]

	certificates, err := h.platform.GetUserCertificates(ctx, userID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get user certificates")
		http.Error(w, "Failed to get certificates", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"certificates": certificates,
		"total":        len(certificates),
	})
}

// GetRecommendations handles GET /api/education/progress/{userId}/recommendations
func (h *EducationHandler) GetRecommendations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userID := vars["userId"]

	recommendations, err := h.platform.GetRecommendations(ctx, userID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get recommendations")
		http.Error(w, "Failed to get recommendations", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"recommendations": recommendations,
		"total":           len(recommendations),
	})
}

// GetUserAnalytics handles GET /api/education/analytics/{userId}
func (h *EducationHandler) GetUserAnalytics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	userID := vars["userId"]

	analytics, err := h.platform.GetUserAnalytics(ctx, userID)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get user analytics")
		http.Error(w, "Failed to get analytics", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(analytics)
}

// Helper function to check if user is admin
func (h *EducationHandler) isAdmin(ctx context.Context) bool {
	role, ok := ctx.Value("user_role").(string)
	return ok && role == "admin"
}
