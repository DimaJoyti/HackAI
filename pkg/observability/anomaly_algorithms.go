package observability

import (
	"context"
	"math"
	"sort"
	"time"
)

// Metric represents a metric data point
type Metric struct {
	Name      string            `json:"name"`
	Value     float64           `json:"value"`
	Timestamp time.Time         `json:"timestamp"`
	Labels    map[string]string `json:"labels"`
	Tags      map[string]string `json:"tags"`
}

// ZScoreAlgorithm implements Z-Score based anomaly detection
type ZScoreAlgorithm struct {
	threshold float64
}

// NewZScoreAlgorithm creates a new Z-Score algorithm
func NewZScoreAlgorithm(threshold float64) *ZScoreAlgorithm {
	return &ZScoreAlgorithm{threshold: threshold}
}

// Name returns the algorithm name
func (z *ZScoreAlgorithm) Name() string {
	return "zscore"
}

// Detect detects anomalies using Z-Score
func (z *ZScoreAlgorithm) Detect(ctx context.Context, data []float64, baseline *Baseline) (*AnomalyResult, error) {
	if len(data) == 0 {
		return &AnomalyResult{IsAnomaly: false}, nil
	}

	// Use the latest value for detection
	currentValue := data[len(data)-1]

	// Calculate Z-Score
	if baseline.StandardDeviation == 0 {
		return &AnomalyResult{IsAnomaly: false}, nil
	}

	zScore := math.Abs(currentValue-baseline.Mean) / baseline.StandardDeviation

	// Determine if anomaly
	isAnomaly := zScore > z.threshold
	confidence := math.Min(zScore/z.threshold, 1.0)

	// Determine severity based on Z-Score
	var severity AnomalySeverity
	switch {
	case zScore > 4.0:
		severity = SeverityCritical
	case zScore > 3.0:
		severity = SeverityHigh
	case zScore > 2.0:
		severity = SeverityMedium
	default:
		severity = SeverityLow
	}

	return &AnomalyResult{
		IsAnomaly:     isAnomaly,
		Confidence:    confidence,
		Severity:      severity,
		Score:         zScore,
		ExpectedValue: baseline.Mean,
		ActualValue:   currentValue,
		Deviation:     math.Abs(currentValue - baseline.Mean),
		Algorithm:     "zscore",
		Context: map[string]interface{}{
			"zscore":          zScore,
			"threshold":       z.threshold,
			"baseline_mean":   baseline.Mean,
			"baseline_stddev": baseline.StandardDeviation,
		},
	}, nil
}

// Train trains the algorithm (no-op for Z-Score)
func (z *ZScoreAlgorithm) Train(ctx context.Context, historicalData []float64) error {
	return nil
}

// GetConfidence returns the confidence level
func (z *ZScoreAlgorithm) GetConfidence() float64 {
	return 0.95
}

// IQRAlgorithm implements Interquartile Range based anomaly detection
type IQRAlgorithm struct {
	multiplier float64
}

// NewIQRAlgorithm creates a new IQR algorithm
func NewIQRAlgorithm(multiplier float64) *IQRAlgorithm {
	return &IQRAlgorithm{multiplier: multiplier}
}

// Name returns the algorithm name
func (i *IQRAlgorithm) Name() string {
	return "iqr"
}

// Detect detects anomalies using IQR
func (i *IQRAlgorithm) Detect(ctx context.Context, data []float64, baseline *Baseline) (*AnomalyResult, error) {
	if len(data) == 0 {
		return &AnomalyResult{IsAnomaly: false}, nil
	}

	currentValue := data[len(data)-1]

	// Get quartiles from baseline
	q1 := baseline.Percentiles["p25"]
	q3 := baseline.Percentiles["p75"]
	iqr := q3 - q1

	// Calculate bounds
	lowerBound := q1 - i.multiplier*iqr
	upperBound := q3 + i.multiplier*iqr

	// Check for anomaly
	isAnomaly := currentValue < lowerBound || currentValue > upperBound

	// Calculate confidence and severity
	var confidence float64
	var severity AnomalySeverity

	if isAnomaly {
		if currentValue < lowerBound {
			deviation := lowerBound - currentValue
			confidence = math.Min(deviation/(iqr*i.multiplier), 1.0)
		} else {
			deviation := currentValue - upperBound
			confidence = math.Min(deviation/(iqr*i.multiplier), 1.0)
		}

		// Determine severity
		switch {
		case confidence > 0.8:
			severity = SeverityCritical
		case confidence > 0.6:
			severity = SeverityHigh
		case confidence > 0.4:
			severity = SeverityMedium
		default:
			severity = SeverityLow
		}
	}

	expectedValue := baseline.Percentiles["p50"] // Use median as expected

	return &AnomalyResult{
		IsAnomaly:     isAnomaly,
		Confidence:    confidence,
		Severity:      severity,
		Score:         confidence,
		ExpectedValue: expectedValue,
		ActualValue:   currentValue,
		Deviation:     math.Abs(currentValue - expectedValue),
		Algorithm:     "iqr",
		Context: map[string]interface{}{
			"q1":          q1,
			"q3":          q3,
			"iqr":         iqr,
			"lower_bound": lowerBound,
			"upper_bound": upperBound,
			"multiplier":  i.multiplier,
		},
	}, nil
}

// Train trains the algorithm (no-op for IQR)
func (i *IQRAlgorithm) Train(ctx context.Context, historicalData []float64) error {
	return nil
}

// GetConfidence returns the confidence level
func (i *IQRAlgorithm) GetConfidence() float64 {
	return 0.90
}

// MADAlgorithm implements Median Absolute Deviation based anomaly detection
type MADAlgorithm struct {
	threshold float64
}

// NewMADAlgorithm creates a new MAD algorithm
func NewMADAlgorithm(threshold float64) *MADAlgorithm {
	return &MADAlgorithm{threshold: threshold}
}

// Name returns the algorithm name
func (m *MADAlgorithm) Name() string {
	return "mad"
}

// Detect detects anomalies using MAD
func (m *MADAlgorithm) Detect(ctx context.Context, data []float64, baseline *Baseline) (*AnomalyResult, error) {
	if len(data) == 0 {
		return &AnomalyResult{IsAnomaly: false}, nil
	}

	currentValue := data[len(data)-1]
	median := baseline.Percentiles["p50"]

	// Calculate MAD from historical data
	mad := m.calculateMAD(data, median)
	if mad == 0 {
		return &AnomalyResult{IsAnomaly: false}, nil
	}

	// Calculate modified Z-Score
	modifiedZScore := 0.6745 * (currentValue - median) / mad

	// Check for anomaly
	isAnomaly := math.Abs(modifiedZScore) > m.threshold
	confidence := math.Min(math.Abs(modifiedZScore)/m.threshold, 1.0)

	// Determine severity
	var severity AnomalySeverity
	absScore := math.Abs(modifiedZScore)
	switch {
	case absScore > 4.0:
		severity = SeverityCritical
	case absScore > 3.0:
		severity = SeverityHigh
	case absScore > 2.0:
		severity = SeverityMedium
	default:
		severity = SeverityLow
	}

	return &AnomalyResult{
		IsAnomaly:     isAnomaly,
		Confidence:    confidence,
		Severity:      severity,
		Score:         absScore,
		ExpectedValue: median,
		ActualValue:   currentValue,
		Deviation:     math.Abs(currentValue - median),
		Algorithm:     "mad",
		Context: map[string]interface{}{
			"modified_zscore": modifiedZScore,
			"mad":             mad,
			"median":          median,
			"threshold":       m.threshold,
		},
	}, nil
}

// calculateMAD calculates Median Absolute Deviation
func (m *MADAlgorithm) calculateMAD(data []float64, median float64) float64 {
	if len(data) == 0 {
		return 0
	}

	deviations := make([]float64, len(data))
	for i, value := range data {
		deviations[i] = math.Abs(value - median)
	}

	sort.Float64s(deviations)

	// Return median of deviations
	n := len(deviations)
	if n%2 == 0 {
		return (deviations[n/2-1] + deviations[n/2]) / 2
	}
	return deviations[n/2]
}

// Train trains the algorithm (no-op for MAD)
func (m *MADAlgorithm) Train(ctx context.Context, historicalData []float64) error {
	return nil
}

// GetConfidence returns the confidence level
func (m *MADAlgorithm) GetConfidence() float64 {
	return 0.92
}

// GrubbsAlgorithm implements Grubbs' test for outliers
type GrubbsAlgorithm struct {
	alpha float64
}

// NewGrubbsAlgorithm creates a new Grubbs algorithm
func NewGrubbsAlgorithm(alpha float64) *GrubbsAlgorithm {
	return &GrubbsAlgorithm{alpha: alpha}
}

// Name returns the algorithm name
func (g *GrubbsAlgorithm) Name() string {
	return "grubbs"
}

// Detect detects anomalies using Grubbs' test
func (g *GrubbsAlgorithm) Detect(ctx context.Context, data []float64, baseline *Baseline) (*AnomalyResult, error) {
	if len(data) < 3 {
		return &AnomalyResult{IsAnomaly: false}, nil
	}

	currentValue := data[len(data)-1]
	mean := baseline.Mean
	stdDev := baseline.StandardDeviation

	if stdDev == 0 {
		return &AnomalyResult{IsAnomaly: false}, nil
	}

	// Calculate Grubbs statistic
	grubbsStatistic := math.Abs(currentValue-mean) / stdDev

	// Critical value for Grubbs test (simplified)
	n := float64(len(data))
	criticalValue := ((n - 1) / math.Sqrt(n)) * math.Sqrt(math.Pow(2.0, 2.0)/(n-2+math.Pow(2.0, 2.0)))

	isAnomaly := grubbsStatistic > criticalValue
	confidence := math.Min(grubbsStatistic/criticalValue, 1.0)

	// Determine severity
	var severity AnomalySeverity
	switch {
	case grubbsStatistic > criticalValue*2:
		severity = SeverityCritical
	case grubbsStatistic > criticalValue*1.5:
		severity = SeverityHigh
	case grubbsStatistic > criticalValue*1.2:
		severity = SeverityMedium
	default:
		severity = SeverityLow
	}

	return &AnomalyResult{
		IsAnomaly:     isAnomaly,
		Confidence:    confidence,
		Severity:      severity,
		Score:         grubbsStatistic,
		ExpectedValue: mean,
		ActualValue:   currentValue,
		Deviation:     math.Abs(currentValue - mean),
		Algorithm:     "grubbs",
		Context: map[string]interface{}{
			"grubbs_statistic": grubbsStatistic,
			"critical_value":   criticalValue,
			"alpha":            g.alpha,
		},
	}, nil
}

// Train trains the algorithm (no-op for Grubbs)
func (g *GrubbsAlgorithm) Train(ctx context.Context, historicalData []float64) error {
	return nil
}

// GetConfidence returns the confidence level
func (g *GrubbsAlgorithm) GetConfidence() float64 {
	return 0.95
}

// Placeholder algorithms for advanced time series and ML-based detection

// SeasonalDecompositionAlgorithm implements seasonal decomposition
type SeasonalDecompositionAlgorithm struct{}

func NewSeasonalDecompositionAlgorithm() *SeasonalDecompositionAlgorithm {
	return &SeasonalDecompositionAlgorithm{}
}

func (s *SeasonalDecompositionAlgorithm) Name() string                                    { return "seasonal_decomposition" }
func (s *SeasonalDecompositionAlgorithm) GetConfidence() float64                          { return 0.85 }
func (s *SeasonalDecompositionAlgorithm) Train(ctx context.Context, data []float64) error { return nil }

func (s *SeasonalDecompositionAlgorithm) Detect(ctx context.Context, data []float64, baseline *Baseline) (*AnomalyResult, error) {
	// Simplified implementation - in production, use proper seasonal decomposition
	if len(data) == 0 {
		return &AnomalyResult{IsAnomaly: false}, nil
	}

	currentValue := data[len(data)-1]
	expectedValue := baseline.Mean

	// Simple threshold-based detection for now
	threshold := 2.0 * baseline.StandardDeviation
	isAnomaly := math.Abs(currentValue-expectedValue) > threshold

	return &AnomalyResult{
		IsAnomaly:     isAnomaly,
		Confidence:    0.85,
		Severity:      SeverityMedium,
		ExpectedValue: expectedValue,
		ActualValue:   currentValue,
		Deviation:     math.Abs(currentValue - expectedValue),
		Algorithm:     "seasonal_decomposition",
	}, nil
}

// ARIMAAlgorithm implements ARIMA-based detection
type ARIMAAlgorithm struct{}

func NewARIMAAlgorithm() *ARIMAAlgorithm                                  { return &ARIMAAlgorithm{} }
func (a *ARIMAAlgorithm) Name() string                                    { return "arima" }
func (a *ARIMAAlgorithm) GetConfidence() float64                          { return 0.88 }
func (a *ARIMAAlgorithm) Train(ctx context.Context, data []float64) error { return nil }

func (a *ARIMAAlgorithm) Detect(ctx context.Context, data []float64, baseline *Baseline) (*AnomalyResult, error) {
	// Placeholder implementation
	if len(data) == 0 {
		return &AnomalyResult{IsAnomaly: false}, nil
	}

	currentValue := data[len(data)-1]
	expectedValue := baseline.Mean

	return &AnomalyResult{
		IsAnomaly:     false,
		Confidence:    0.88,
		ExpectedValue: expectedValue,
		ActualValue:   currentValue,
		Algorithm:     "arima",
	}, nil
}

// ExponentialSmoothingAlgorithm implements exponential smoothing
type ExponentialSmoothingAlgorithm struct{}

func NewExponentialSmoothingAlgorithm() *ExponentialSmoothingAlgorithm {
	return &ExponentialSmoothingAlgorithm{}
}
func (e *ExponentialSmoothingAlgorithm) Name() string                                    { return "exponential_smoothing" }
func (e *ExponentialSmoothingAlgorithm) GetConfidence() float64                          { return 0.82 }
func (e *ExponentialSmoothingAlgorithm) Train(ctx context.Context, data []float64) error { return nil }

func (e *ExponentialSmoothingAlgorithm) Detect(ctx context.Context, data []float64, baseline *Baseline) (*AnomalyResult, error) {
	// Placeholder implementation
	if len(data) == 0 {
		return &AnomalyResult{IsAnomaly: false}, nil
	}

	currentValue := data[len(data)-1]
	expectedValue := baseline.Mean

	return &AnomalyResult{
		IsAnomaly:     false,
		Confidence:    0.82,
		ExpectedValue: expectedValue,
		ActualValue:   currentValue,
		Algorithm:     "exponential_smoothing",
	}, nil
}

// IsolationForestAlgorithm implements isolation forest
type IsolationForestAlgorithm struct{}

func NewIsolationForestAlgorithm() *IsolationForestAlgorithm                        { return &IsolationForestAlgorithm{} }
func (i *IsolationForestAlgorithm) Name() string                                    { return "isolation_forest" }
func (i *IsolationForestAlgorithm) GetConfidence() float64                          { return 0.90 }
func (i *IsolationForestAlgorithm) Train(ctx context.Context, data []float64) error { return nil }

func (i *IsolationForestAlgorithm) Detect(ctx context.Context, data []float64, baseline *Baseline) (*AnomalyResult, error) {
	// Placeholder implementation
	if len(data) == 0 {
		return &AnomalyResult{IsAnomaly: false}, nil
	}

	currentValue := data[len(data)-1]
	expectedValue := baseline.Mean

	return &AnomalyResult{
		IsAnomaly:     false,
		Confidence:    0.90,
		ExpectedValue: expectedValue,
		ActualValue:   currentValue,
		Algorithm:     "isolation_forest",
	}, nil
}

// OneClassSVMAlgorithm implements One-Class SVM
type OneClassSVMAlgorithm struct{}

func NewOneClassSVMAlgorithm() *OneClassSVMAlgorithm                            { return &OneClassSVMAlgorithm{} }
func (o *OneClassSVMAlgorithm) Name() string                                    { return "one_class_svm" }
func (o *OneClassSVMAlgorithm) GetConfidence() float64                          { return 0.87 }
func (o *OneClassSVMAlgorithm) Train(ctx context.Context, data []float64) error { return nil }

func (o *OneClassSVMAlgorithm) Detect(ctx context.Context, data []float64, baseline *Baseline) (*AnomalyResult, error) {
	// Placeholder implementation
	if len(data) == 0 {
		return &AnomalyResult{IsAnomaly: false}, nil
	}

	currentValue := data[len(data)-1]
	expectedValue := baseline.Mean

	return &AnomalyResult{
		IsAnomaly:     false,
		Confidence:    0.87,
		ExpectedValue: expectedValue,
		ActualValue:   currentValue,
		Algorithm:     "one_class_svm",
	}, nil
}

// AutoencoderAlgorithm implements autoencoder-based detection
type AutoencoderAlgorithm struct{}

func NewAutoencoderAlgorithm() *AutoencoderAlgorithm                            { return &AutoencoderAlgorithm{} }
func (a *AutoencoderAlgorithm) Name() string                                    { return "autoencoder" }
func (a *AutoencoderAlgorithm) GetConfidence() float64                          { return 0.92 }
func (a *AutoencoderAlgorithm) Train(ctx context.Context, data []float64) error { return nil }

func (a *AutoencoderAlgorithm) Detect(ctx context.Context, data []float64, baseline *Baseline) (*AnomalyResult, error) {
	// Placeholder implementation
	if len(data) == 0 {
		return &AnomalyResult{IsAnomaly: false}, nil
	}

	currentValue := data[len(data)-1]
	expectedValue := baseline.Mean

	return &AnomalyResult{
		IsAnomaly:     false,
		Confidence:    0.92,
		ExpectedValue: expectedValue,
		ActualValue:   currentValue,
		Algorithm:     "autoencoder",
	}, nil
}
