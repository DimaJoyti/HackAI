package education

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// AssessmentEngine manages educational assessments and evaluations
type AssessmentEngine struct {
	logger      *logger.Logger
	assessments map[string]*Assessment
	attempts    map[string]*AssessmentAttempt
	config      *AssessmentConfig
	mu          sync.RWMutex
}

// AssessmentConfig configuration for assessment engine
type AssessmentConfig struct {
	EnableAdaptiveAssessment bool          `json:"enable_adaptive_assessment"`
	EnableTimedAssessments   bool          `json:"enable_timed_assessments"`
	EnableRetakes            bool          `json:"enable_retakes"`
	MaxRetakeAttempts        int           `json:"max_retake_attempts"`
	PassingScore             float64       `json:"passing_score"`
	EnablePlagiarismCheck    bool          `json:"enable_plagiarism_check"`
	EnableProctoring         bool          `json:"enable_proctoring"`
	RandomizeQuestions       bool          `json:"randomize_questions"`
	ShowCorrectAnswers       bool          `json:"show_correct_answers"`
	ImmediateFeedback        bool          `json:"immediate_feedback"`
}

// Assessment represents an educational assessment
type Assessment struct {
	ID              string                 `json:"id"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	Type            string                 `json:"type"`
	Category        string                 `json:"category"`
	Difficulty      string                 `json:"difficulty"`
	TimeLimit       *time.Duration         `json:"time_limit"`
	PassingScore    float64                `json:"passing_score"`
	MaxAttempts     int                    `json:"max_attempts"`
	Questions       []*Question            `json:"questions"`
	Instructions    string                 `json:"instructions"`
	Prerequisites   []string               `json:"prerequisites"`
	Tags            []string               `json:"tags"`
	Metadata        map[string]interface{} `json:"metadata"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

// Question represents an assessment question
type Question struct {
	ID              string                 `json:"id"`
	Type            string                 `json:"type"`
	Title           string                 `json:"title"`
	Content         string                 `json:"content"`
	Points          float64                `json:"points"`
	Options         []*QuestionOption      `json:"options"`
	CorrectAnswers  []string               `json:"correct_answers"`
	Explanation     string                 `json:"explanation"`
	Hints           []string               `json:"hints"`
	Tags            []string               `json:"tags"`
	Difficulty      string                 `json:"difficulty"`
	EstimatedTime   time.Duration          `json:"estimated_time"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// QuestionOption represents a question option
type QuestionOption struct {
	ID          string                 `json:"id"`
	Text        string                 `json:"text"`
	IsCorrect   bool                   `json:"is_correct"`
	Explanation string                 `json:"explanation"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AssessmentAttempt represents an assessment attempt
type AssessmentAttempt struct {
	ID              string                 `json:"id"`
	AssessmentID    string                 `json:"assessment_id"`
	UserID          string                 `json:"user_id"`
	AttemptNumber   int                    `json:"attempt_number"`
	Status          string                 `json:"status"`
	StartTime       time.Time              `json:"start_time"`
	EndTime         *time.Time             `json:"end_time"`
	TimeSpent       time.Duration          `json:"time_spent"`
	Responses       []*QuestionResponse    `json:"responses"`
	Score           float64                `json:"score"`
	MaxScore        float64                `json:"max_score"`
	Percentage      float64                `json:"percentage"`
	Passed          bool                   `json:"passed"`
	Feedback        *AssessmentFeedback    `json:"feedback"`
	Analytics       *AttemptAnalytics      `json:"analytics"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// QuestionResponse represents a response to a question
type QuestionResponse struct {
	QuestionID      string                 `json:"question_id"`
	Response        interface{}            `json:"response"`
	IsCorrect       bool                   `json:"is_correct"`
	PartialCredit   float64                `json:"partial_credit"`
	TimeSpent       time.Duration          `json:"time_spent"`
	Attempts        int                    `json:"attempts"`
	HintsUsed       []string               `json:"hints_used"`
	Confidence      float64                `json:"confidence"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// AssessmentFeedback represents feedback for an assessment attempt
type AssessmentFeedback struct {
	OverallFeedback     string                    `json:"overall_feedback"`
	QuestionFeedback    map[string]string         `json:"question_feedback"`
	StrengthAreas       []string                  `json:"strength_areas"`
	ImprovementAreas    []string                  `json:"improvement_areas"`
	Recommendations     []string                  `json:"recommendations"`
	NextSteps           []string                  `json:"next_steps"`
	StudyResources      []*Resource               `json:"study_resources"`
	Metadata            map[string]interface{}    `json:"metadata"`
}

// AttemptAnalytics represents analytics for an assessment attempt
type AttemptAnalytics struct {
	TotalQuestions      int                    `json:"total_questions"`
	CorrectAnswers      int                    `json:"correct_answers"`
	IncorrectAnswers    int                    `json:"incorrect_answers"`
	SkippedQuestions    int                    `json:"skipped_questions"`
	AverageTimePerQ     time.Duration          `json:"average_time_per_question"`
	DifficultyBreakdown map[string]int         `json:"difficulty_breakdown"`
	CategoryBreakdown   map[string]float64     `json:"category_breakdown"`
	ConfidenceAnalysis  *ConfidenceAnalysis    `json:"confidence_analysis"`
	Metadata            map[string]interface{} `json:"metadata"`
}

// ConfidenceAnalysis represents confidence analysis
type ConfidenceAnalysis struct {
	AverageConfidence   float64 `json:"average_confidence"`
	OverconfidentCount  int     `json:"overconfident_count"`
	UnderconfidentCount int     `json:"underconfident_count"`
	CalibrationScore    float64 `json:"calibration_score"`
}

// Achievement represents a learning achievement
type Achievement struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"`
	Category    string                 `json:"category"`
	Points      int                    `json:"points"`
	BadgeURL    string                 `json:"badge_url"`
	Criteria    map[string]interface{} `json:"criteria"`
	EarnedAt    time.Time              `json:"earned_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// NewAssessmentEngine creates a new assessment engine
func NewAssessmentEngine(logger *logger.Logger) *AssessmentEngine {
	engine := &AssessmentEngine{
		logger:      logger,
		assessments: make(map[string]*Assessment),
		attempts:    make(map[string]*AssessmentAttempt),
		config: &AssessmentConfig{
			EnableAdaptiveAssessment: true,
			EnableTimedAssessments:   true,
			EnableRetakes:            true,
			MaxRetakeAttempts:        3,
			PassingScore:             70.0,
			EnablePlagiarismCheck:    true,
			EnableProctoring:         false,
			RandomizeQuestions:       true,
			ShowCorrectAnswers:       true,
			ImmediateFeedback:        true,
		},
	}

	engine.initializeDefaultAssessments()
	return engine
}

// initializeDefaultAssessments creates default assessments
func (ae *AssessmentEngine) initializeDefaultAssessments() {
	// AI Security Fundamentals Quiz
	fundamentalsQuiz := &Assessment{
		ID:           "ai-security-fundamentals-quiz",
		Title:        "AI Security Fundamentals Assessment",
		Description:  "Comprehensive assessment of AI security fundamentals knowledge",
		Type:         "quiz",
		Category:     "fundamentals",
		Difficulty:   "beginner",
		TimeLimit:    &[]time.Duration{45 * time.Minute}[0],
		PassingScore: 70.0,
		MaxAttempts:  3,
		Instructions: "Answer all questions to the best of your ability. You have 45 minutes to complete this assessment.",
		Questions: []*Question{
			{
				ID:      "q1",
				Type:    "multiple_choice",
				Title:   "AI Threat Categories",
				Content: "Which of the following is NOT a major category of AI security threats?",
				Points:  10.0,
				Options: []*QuestionOption{
					{ID: "a", Text: "Adversarial Attacks", IsCorrect: false},
					{ID: "b", Text: "Data Poisoning", IsCorrect: false},
					{ID: "c", Text: "Network Latency", IsCorrect: true},
					{ID: "d", Text: "Model Extraction", IsCorrect: false},
				},
				CorrectAnswers: []string{"c"},
				Explanation:    "Network latency is a performance issue, not a security threat. The other options are all major AI security threat categories.",
				Difficulty:     "easy",
				EstimatedTime:  2 * time.Minute,
			},
			{
				ID:      "q2",
				Type:    "multiple_choice",
				Title:   "Prompt Injection",
				Content: "What is the primary goal of a prompt injection attack?",
				Points:  10.0,
				Options: []*QuestionOption{
					{ID: "a", Text: "Improve model performance", IsCorrect: false},
					{ID: "b", Text: "Bypass security controls", IsCorrect: true},
					{ID: "c", Text: "Reduce computational costs", IsCorrect: false},
					{ID: "d", Text: "Enhance user experience", IsCorrect: false},
				},
				CorrectAnswers: []string{"b"},
				Explanation:    "Prompt injection attacks aim to bypass security controls and manipulate AI system behavior.",
				Difficulty:     "medium",
				EstimatedTime:  3 * time.Minute,
			},
			{
				ID:      "q3",
				Type:    "multiple_select",
				Title:   "MITRE ATLAS Framework",
				Content: "Which of the following are tactics in the MITRE ATLAS framework? (Select all that apply)",
				Points:  15.0,
				Options: []*QuestionOption{
					{ID: "a", Text: "Initial Access", IsCorrect: true},
					{ID: "b", Text: "Execution", IsCorrect: true},
					{ID: "c", Text: "Compilation", IsCorrect: false},
					{ID: "d", Text: "Defense Evasion", IsCorrect: true},
					{ID: "e", Text: "Data Visualization", IsCorrect: false},
				},
				CorrectAnswers: []string{"a", "b", "d"},
				Explanation:    "Initial Access, Execution, and Defense Evasion are all tactics in the MITRE ATLAS framework.",
				Difficulty:     "medium",
				EstimatedTime:  4 * time.Minute,
			},
			{
				ID:      "q4",
				Type:    "short_answer",
				Title:   "Security Controls",
				Content: "Describe three key security controls that should be implemented to protect AI systems from prompt injection attacks.",
				Points:  20.0,
				Explanation: "Key controls include: input validation and sanitization, prompt templates with parameter binding, output filtering, rate limiting, and monitoring/logging.",
				Difficulty:  "hard",
				EstimatedTime: 8 * time.Minute,
			},
		},
		Tags:      []string{"ai-security", "fundamentals", "assessment"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Metadata:  make(map[string]interface{}),
	}

	// Advanced AI Security Assessment
	advancedAssessment := &Assessment{
		ID:           "advanced-ai-security-assessment",
		Title:        "Advanced AI Security Assessment",
		Description:  "Comprehensive assessment of advanced AI security concepts and practices",
		Type:         "comprehensive",
		Category:     "advanced",
		Difficulty:   "advanced",
		TimeLimit:    &[]time.Duration{90 * time.Minute}[0],
		PassingScore: 75.0,
		MaxAttempts:  2,
		Instructions: "This assessment covers advanced AI security topics. Take your time and provide detailed answers.",
		Questions: []*Question{
			{
				ID:      "adv1",
				Type:    "scenario",
				Title:   "Red Team Assessment",
				Content: "You are conducting a red team assessment of an AI-powered customer service system. Describe your methodology and the key attack vectors you would test.",
				Points:  25.0,
				Explanation: "A comprehensive red team assessment should include prompt injection testing, model extraction attempts, adversarial input generation, and social engineering scenarios.",
				Difficulty: "hard",
				EstimatedTime: 15 * time.Minute,
			},
			{
				ID:      "adv2",
				Type:    "case_study",
				Title:   "Incident Response",
				Content: "An AI model in production has been compromised through a data poisoning attack. Outline your incident response plan and remediation steps.",
				Points:  25.0,
				Explanation: "Response should include immediate containment, forensic analysis, model retraining with clean data, and implementation of additional monitoring.",
				Difficulty: "expert",
				EstimatedTime: 20 * time.Minute,
			},
		},
		Tags:      []string{"ai-security", "advanced", "red-team", "incident-response"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Metadata:  make(map[string]interface{}),
	}

	// Add assessments to engine
	ae.assessments[fundamentalsQuiz.ID] = fundamentalsQuiz
	ae.assessments[advancedAssessment.ID] = advancedAssessment
}

// StartAssessment starts a new assessment attempt
func (ae *AssessmentEngine) StartAssessment(ctx context.Context, assessmentID, userID string) (*AssessmentAttempt, error) {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	// Get assessment
	assessment, exists := ae.assessments[assessmentID]
	if !exists {
		return nil, fmt.Errorf("assessment not found: %s", assessmentID)
	}

	// Check previous attempts
	attemptNumber := ae.countUserAttempts(assessmentID, userID) + 1
	if attemptNumber > assessment.MaxAttempts {
		return nil, fmt.Errorf("maximum attempts exceeded for assessment: %s", assessmentID)
	}

	attempt := &AssessmentAttempt{
		ID:            uuid.New().String(),
		AssessmentID:  assessmentID,
		UserID:        userID,
		AttemptNumber: attemptNumber,
		Status:        "in_progress",
		StartTime:     time.Now(),
		Responses:     make([]*QuestionResponse, 0),
		MaxScore:      ae.calculateMaxScore(assessment),
		Metadata:      make(map[string]interface{}),
	}

	ae.attempts[attempt.ID] = attempt

	ae.logger.WithFields(map[string]interface{}{
		"attempt_id":    attempt.ID,
		"assessment_id": assessmentID,
		"user_id":       userID,
		"attempt_number": attemptNumber,
	}).Info("Assessment attempt started")

	return attempt, nil
}

// SubmitResponse submits a response to a question
func (ae *AssessmentEngine) SubmitResponse(attemptID, questionID string, response interface{}) (*QuestionResponse, error) {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	attempt, exists := ae.attempts[attemptID]
	if !exists {
		return nil, fmt.Errorf("assessment attempt not found: %s", attemptID)
	}

	if attempt.Status != "in_progress" {
		return nil, fmt.Errorf("assessment attempt is not in progress")
	}

	// Get assessment and question
	assessment := ae.assessments[attempt.AssessmentID]
	var question *Question
	for _, q := range assessment.Questions {
		if q.ID == questionID {
			question = q
			break
		}
	}

	if question == nil {
		return nil, fmt.Errorf("question not found: %s", questionID)
	}

	// Evaluate response
	isCorrect, partialCredit := ae.evaluateResponse(question, response)

	questionResponse := &QuestionResponse{
		QuestionID:    questionID,
		Response:      response,
		IsCorrect:     isCorrect,
		PartialCredit: partialCredit,
		TimeSpent:     time.Since(attempt.StartTime), // Simplified
		Attempts:      1,
		HintsUsed:     []string{},
		Confidence:    0.8, // Would be provided by user
		Metadata:      make(map[string]interface{}),
	}

	// Update or add response
	found := false
	for i, resp := range attempt.Responses {
		if resp.QuestionID == questionID {
			attempt.Responses[i] = questionResponse
			found = true
			break
		}
	}
	if !found {
		attempt.Responses = append(attempt.Responses, questionResponse)
	}

	return questionResponse, nil
}

// FinishAssessment completes an assessment attempt
func (ae *AssessmentEngine) FinishAssessment(attemptID string) (*AssessmentAttempt, error) {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	attempt, exists := ae.attempts[attemptID]
	if !exists {
		return nil, fmt.Errorf("assessment attempt not found: %s", attemptID)
	}

	if attempt.Status != "in_progress" {
		return nil, fmt.Errorf("assessment attempt is not in progress")
	}

	// Calculate final score
	attempt.Score = ae.calculateScore(attempt)
	attempt.Percentage = (attempt.Score / attempt.MaxScore) * 100
	attempt.Passed = attempt.Percentage >= ae.assessments[attempt.AssessmentID].PassingScore

	// Set end time and status
	endTime := time.Now()
	attempt.EndTime = &endTime
	attempt.TimeSpent = endTime.Sub(attempt.StartTime)
	attempt.Status = "completed"

	// Generate feedback and analytics
	attempt.Feedback = ae.generateFeedback(attempt)
	attempt.Analytics = ae.generateAnalytics(attempt)

	ae.logger.WithFields(map[string]interface{}{
		"attempt_id": attempt.ID,
		"score":      attempt.Score,
		"percentage": attempt.Percentage,
		"passed":     attempt.Passed,
	}).Info("Assessment attempt completed")

	return attempt, nil
}

// evaluateResponse evaluates a question response
func (ae *AssessmentEngine) evaluateResponse(question *Question, response interface{}) (bool, float64) {
	switch question.Type {
	case "multiple_choice":
		if responseStr, ok := response.(string); ok {
			for _, correct := range question.CorrectAnswers {
				if responseStr == correct {
					return true, 1.0
				}
			}
		}
		return false, 0.0

	case "multiple_select":
		if responseSlice, ok := response.([]string); ok {
			correctCount := 0
			totalCorrect := len(question.CorrectAnswers)
			
			for _, resp := range responseSlice {
				for _, correct := range question.CorrectAnswers {
					if resp == correct {
						correctCount++
						break
					}
				}
			}
			
			if correctCount == totalCorrect && len(responseSlice) == totalCorrect {
				return true, 1.0
			}
			
			// Partial credit
			partialCredit := float64(correctCount) / float64(totalCorrect)
			return false, partialCredit
		}
		return false, 0.0

	case "short_answer", "scenario", "case_study":
		// For text responses, would use NLP evaluation or manual grading
		// Simplified for demo
		return true, 0.8

	default:
		return false, 0.0
	}
}

// calculateScore calculates the total score for an attempt
func (ae *AssessmentEngine) calculateScore(attempt *AssessmentAttempt) float64 {
	assessment := ae.assessments[attempt.AssessmentID]
	totalScore := 0.0

	for _, response := range attempt.Responses {
		for _, question := range assessment.Questions {
			if question.ID == response.QuestionID {
				if response.IsCorrect {
					totalScore += question.Points
				} else {
					totalScore += question.Points * response.PartialCredit
				}
				break
			}
		}
	}

	return totalScore
}

// calculateMaxScore calculates the maximum possible score
func (ae *AssessmentEngine) calculateMaxScore(assessment *Assessment) float64 {
	maxScore := 0.0
	for _, question := range assessment.Questions {
		maxScore += question.Points
	}
	return maxScore
}

// countUserAttempts counts the number of attempts by a user for an assessment
func (ae *AssessmentEngine) countUserAttempts(assessmentID, userID string) int {
	count := 0
	for _, attempt := range ae.attempts {
		if attempt.AssessmentID == assessmentID && attempt.UserID == userID {
			count++
		}
	}
	return count
}

// generateFeedback generates feedback for an assessment attempt
func (ae *AssessmentEngine) generateFeedback(attempt *AssessmentAttempt) *AssessmentFeedback {
	feedback := &AssessmentFeedback{
		QuestionFeedback: make(map[string]string),
		StrengthAreas:    []string{},
		ImprovementAreas: []string{},
		Recommendations:  []string{},
		NextSteps:        []string{},
		StudyResources:   []*Resource{},
		Metadata:         make(map[string]interface{}),
	}

	if attempt.Passed {
		feedback.OverallFeedback = "Congratulations! You have successfully passed this assessment."
		feedback.NextSteps = []string{
			"Proceed to the next module",
			"Apply your knowledge in practical labs",
		}
	} else {
		feedback.OverallFeedback = "You did not pass this assessment. Review the feedback and try again."
		feedback.Recommendations = []string{
			"Review the course materials",
			"Practice with additional exercises",
			"Seek help from instructors",
		}
	}

	return feedback
}

// generateAnalytics generates analytics for an assessment attempt
func (ae *AssessmentEngine) generateAnalytics(attempt *AssessmentAttempt) *AttemptAnalytics {
	analytics := &AttemptAnalytics{
		TotalQuestions:      len(attempt.Responses),
		DifficultyBreakdown: make(map[string]int),
		CategoryBreakdown:   make(map[string]float64),
		Metadata:            make(map[string]interface{}),
	}

	correctCount := 0
	totalTime := time.Duration(0)

	for _, response := range attempt.Responses {
		if response.IsCorrect {
			correctCount++
		}
		totalTime += response.TimeSpent
	}

	analytics.CorrectAnswers = correctCount
	analytics.IncorrectAnswers = analytics.TotalQuestions - correctCount
	
	if analytics.TotalQuestions > 0 {
		analytics.AverageTimePerQ = totalTime / time.Duration(analytics.TotalQuestions)
	}

	// Calculate confidence analysis
	totalConfidence := 0.0
	overconfident := 0
	underconfident := 0

	for _, response := range attempt.Responses {
		totalConfidence += response.Confidence
		
		if response.Confidence > 0.8 && !response.IsCorrect {
			overconfident++
		}
		if response.Confidence < 0.5 && response.IsCorrect {
			underconfident++
		}
	}

	analytics.ConfidenceAnalysis = &ConfidenceAnalysis{
		AverageConfidence:   totalConfidence / float64(len(attempt.Responses)),
		OverconfidentCount:  overconfident,
		UnderconfidentCount: underconfident,
		CalibrationScore:    ae.calculateCalibrationScore(attempt.Responses),
	}

	return analytics
}

// calculateCalibrationScore calculates confidence calibration score
func (ae *AssessmentEngine) calculateCalibrationScore(responses []*QuestionResponse) float64 {
	if len(responses) == 0 {
		return 0.0
	}

	totalError := 0.0
	for _, response := range responses {
		actualCorrectness := 0.0
		if response.IsCorrect {
			actualCorrectness = 1.0
		}
		error := math.Abs(response.Confidence - actualCorrectness)
		totalError += error
	}

	// Return calibration score (lower is better, so we invert it)
	return 1.0 - (totalError / float64(len(responses)))
}
