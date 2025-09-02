package ai

import (
	"bytes"
	"compress/gzip"
	"compress/lzw"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

// CompressionType represents different compression algorithms
type CompressionType string

const (
	CompressionNone CompressionType = "none"
	CompressionGzip CompressionType = "gzip"
	CompressionLZ4  CompressionType = "lz4"
	CompressionZstd CompressionType = "zstd"
	CompressionLZW  CompressionType = "lzw"
)

// Compressor interface for different compression algorithms
type Compressor interface {
	Compress(data []byte) ([]byte, error)
	Decompress(data []byte) ([]byte, error)
	Type() CompressionType
	CompressionRatio(originalSize, compressedSize int) float64
}

// CompressionManager manages compression operations
type CompressionManager struct {
	compressors map[CompressionType]Compressor
	defaultType CompressionType
}

// NewCompressionManager creates a new compression manager
func NewCompressionManager(defaultType CompressionType) *CompressionManager {
	cm := &CompressionManager{
		compressors: make(map[CompressionType]Compressor),
		defaultType: defaultType,
	}

	// Register built-in compressors
	cm.RegisterCompressor(&GzipCompressor{})
	cm.RegisterCompressor(&LZ4Compressor{})
	cm.RegisterCompressor(&ZstdCompressor{})
	cm.RegisterCompressor(&LZWCompressor{})
	cm.RegisterCompressor(&NoCompressor{})

	return cm
}

// RegisterCompressor registers a new compressor
func (cm *CompressionManager) RegisterCompressor(compressor Compressor) {
	cm.compressors[compressor.Type()] = compressor
}

// Compress compresses data using the specified compression type
func (cm *CompressionManager) Compress(data []byte, compressionType CompressionType) ([]byte, error) {
	if compressionType == CompressionNone {
		compressionType = cm.defaultType
	}

	compressor, exists := cm.compressors[compressionType]
	if !exists {
		return nil, fmt.Errorf("unsupported compression type: %s", compressionType)
	}

	return compressor.Compress(data)
}

// Decompress decompresses data using the specified compression type
func (cm *CompressionManager) Decompress(data []byte, compressionType CompressionType) ([]byte, error) {
	compressor, exists := cm.compressors[compressionType]
	if !exists {
		return nil, fmt.Errorf("unsupported compression type: %s", compressionType)
	}

	return compressor.Decompress(data)
}

// GetCompressionRatio calculates compression ratio
func (cm *CompressionManager) GetCompressionRatio(originalSize, compressedSize int, compressionType CompressionType) float64 {
	compressor, exists := cm.compressors[compressionType]
	if !exists {
		return 1.0
	}

	return compressor.CompressionRatio(originalSize, compressedSize)
}

// GzipCompressor implements gzip compression
type GzipCompressor struct{}

func (g *GzipCompressor) Type() CompressionType { return CompressionGzip }

func (g *GzipCompressor) Compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)

	if _, err := writer.Write(data); err != nil {
		return nil, err
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (g *GzipCompressor) Decompress(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	return io.ReadAll(reader)
}

func (g *GzipCompressor) CompressionRatio(originalSize, compressedSize int) float64 {
	if originalSize == 0 {
		return 1.0
	}
	return float64(compressedSize) / float64(originalSize)
}

// LZ4Compressor implements LZ4 compression
type LZ4Compressor struct{}

func (l *LZ4Compressor) Type() CompressionType { return CompressionLZ4 }

func (l *LZ4Compressor) Compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := lz4.NewWriter(&buf)

	if _, err := writer.Write(data); err != nil {
		return nil, err
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (l *LZ4Compressor) Decompress(data []byte) ([]byte, error) {
	reader := lz4.NewReader(bytes.NewReader(data))
	return io.ReadAll(reader)
}

func (l *LZ4Compressor) CompressionRatio(originalSize, compressedSize int) float64 {
	if originalSize == 0 {
		return 1.0
	}
	return float64(compressedSize) / float64(originalSize)
}

// ZstdCompressor implements Zstandard compression
type ZstdCompressor struct {
	encoder *zstd.Encoder
	decoder *zstd.Decoder
}

func (z *ZstdCompressor) Type() CompressionType { return CompressionZstd }

func (z *ZstdCompressor) Compress(data []byte) ([]byte, error) {
	if z.encoder == nil {
		var err error
		z.encoder, err = zstd.NewWriter(nil)
		if err != nil {
			return nil, err
		}
	}

	return z.encoder.EncodeAll(data, make([]byte, 0, len(data))), nil
}

func (z *ZstdCompressor) Decompress(data []byte) ([]byte, error) {
	if z.decoder == nil {
		var err error
		z.decoder, err = zstd.NewReader(nil)
		if err != nil {
			return nil, err
		}
	}

	return z.decoder.DecodeAll(data, nil)
}

func (z *ZstdCompressor) CompressionRatio(originalSize, compressedSize int) float64 {
	if originalSize == 0 {
		return 1.0
	}
	return float64(compressedSize) / float64(originalSize)
}

// LZWCompressor implements LZW compression
type LZWCompressor struct{}

func (l *LZWCompressor) Type() CompressionType { return CompressionLZW }

func (l *LZWCompressor) Compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := lzw.NewWriter(&buf, lzw.LSB, 8)

	if _, err := writer.Write(data); err != nil {
		return nil, err
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (l *LZWCompressor) Decompress(data []byte) ([]byte, error) {
	reader := lzw.NewReader(bytes.NewReader(data), lzw.LSB, 8)
	defer reader.Close()

	return io.ReadAll(reader)
}

func (l *LZWCompressor) CompressionRatio(originalSize, compressedSize int) float64 {
	if originalSize == 0 {
		return 1.0
	}
	return float64(compressedSize) / float64(originalSize)
}

// NoCompressor implements no compression (pass-through)
type NoCompressor struct{}

func (n *NoCompressor) Type() CompressionType { return CompressionNone }

func (n *NoCompressor) Compress(data []byte) ([]byte, error) {
	return data, nil
}

func (n *NoCompressor) Decompress(data []byte) ([]byte, error) {
	return data, nil
}

func (n *NoCompressor) CompressionRatio(originalSize, compressedSize int) float64 {
	return 1.0
}

// CompressionStats tracks compression statistics
type CompressionStats struct {
	TotalOperations     int64   `json:"total_operations"`
	TotalOriginalSize   int64   `json:"total_original_size"`
	TotalCompressedSize int64   `json:"total_compressed_size"`
	AverageRatio        float64 `json:"average_ratio"`
	CompressionTime     int64   `json:"compression_time_ns"`
	DecompressionTime   int64   `json:"decompression_time_ns"`
}

// UpdateStats updates compression statistics
func (cs *CompressionStats) UpdateStats(originalSize, compressedSize int, compressionTime, decompressionTime int64) {
	cs.TotalOperations++
	cs.TotalOriginalSize += int64(originalSize)
	cs.TotalCompressedSize += int64(compressedSize)
	cs.CompressionTime += compressionTime
	cs.DecompressionTime += decompressionTime

	if cs.TotalOriginalSize > 0 {
		cs.AverageRatio = float64(cs.TotalCompressedSize) / float64(cs.TotalOriginalSize)
	}
}

// GetCompressionEfficiency returns compression efficiency metrics
func (cs *CompressionStats) GetCompressionEfficiency() map[string]interface{} {
	return map[string]interface{}{
		"space_saved_bytes":         cs.TotalOriginalSize - cs.TotalCompressedSize,
		"space_saved_percent":       (1.0 - cs.AverageRatio) * 100,
		"avg_compression_time_ms":   float64(cs.CompressionTime) / float64(cs.TotalOperations) / 1e6,
		"avg_decompression_time_ms": float64(cs.DecompressionTime) / float64(cs.TotalOperations) / 1e6,
	}
}
