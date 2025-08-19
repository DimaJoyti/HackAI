package ai

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

// EncryptionType represents different encryption algorithms
type EncryptionType string

const (
	EncryptionNone        EncryptionType = "none"
	EncryptionAES256GCM   EncryptionType = "aes256gcm"
	EncryptionChaCha20    EncryptionType = "chacha20poly1305"
)

// Encryptor interface for different encryption algorithms
type Encryptor interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
	Type() EncryptionType
	KeySize() int
}

// EncryptionManager manages encryption operations
type EncryptionManager struct {
	encryptors  map[EncryptionType]Encryptor
	defaultType EncryptionType
	masterKey   []byte
}

// NewEncryptionManager creates a new encryption manager
func NewEncryptionManager(masterKey []byte, defaultType EncryptionType) (*EncryptionManager, error) {
	if len(masterKey) == 0 {
		return nil, fmt.Errorf("master key cannot be empty")
	}

	em := &EncryptionManager{
		encryptors:  make(map[EncryptionType]Encryptor),
		defaultType: defaultType,
		masterKey:   masterKey,
	}

	// Register built-in encryptors
	if err := em.registerBuiltinEncryptors(); err != nil {
		return nil, err
	}

	return em, nil
}

// registerBuiltinEncryptors registers built-in encryption algorithms
func (em *EncryptionManager) registerBuiltinEncryptors() error {
	// AES-256-GCM
	aesEncryptor, err := NewAESGCMEncryptor(em.masterKey)
	if err != nil {
		return err
	}
	em.RegisterEncryptor(aesEncryptor)

	// ChaCha20-Poly1305
	chachaEncryptor, err := NewChaCha20Encryptor(em.masterKey)
	if err != nil {
		return err
	}
	em.RegisterEncryptor(chachaEncryptor)

	// No encryption
	em.RegisterEncryptor(&NoEncryptor{})

	return nil
}

// RegisterEncryptor registers a new encryptor
func (em *EncryptionManager) RegisterEncryptor(encryptor Encryptor) {
	em.encryptors[encryptor.Type()] = encryptor
}

// Encrypt encrypts data using the specified encryption type
func (em *EncryptionManager) Encrypt(data []byte, encryptionType EncryptionType) ([]byte, error) {
	if encryptionType == EncryptionNone {
		encryptionType = em.defaultType
	}

	encryptor, exists := em.encryptors[encryptionType]
	if !exists {
		return nil, fmt.Errorf("unsupported encryption type: %s", encryptionType)
	}

	return encryptor.Encrypt(data)
}

// Decrypt decrypts data using the specified encryption type
func (em *EncryptionManager) Decrypt(data []byte, encryptionType EncryptionType) ([]byte, error) {
	encryptor, exists := em.encryptors[encryptionType]
	if !exists {
		return nil, fmt.Errorf("unsupported encryption type: %s", encryptionType)
	}

	return encryptor.Decrypt(data)
}

// DeriveKey derives a key from a password using scrypt
func DeriveKey(password, salt []byte, keyLen int) ([]byte, error) {
	return scrypt.Key(password, salt, 32768, 8, 1, keyLen)
}

// GenerateSalt generates a random salt
func GenerateSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// AESGCMEncryptor implements AES-256-GCM encryption
type AESGCMEncryptor struct {
	gcm cipher.AEAD
}

// NewAESGCMEncryptor creates a new AES-GCM encryptor
func NewAESGCMEncryptor(key []byte) (*AESGCMEncryptor, error) {
	// Ensure key is 32 bytes for AES-256
	if len(key) != 32 {
		hash := sha256.Sum256(key)
		key = hash[:]
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &AESGCMEncryptor{gcm: gcm}, nil
}

func (a *AESGCMEncryptor) Type() EncryptionType { return EncryptionAES256GCM }
func (a *AESGCMEncryptor) KeySize() int         { return 32 }

func (a *AESGCMEncryptor) Encrypt(data []byte) ([]byte, error) {
	nonce := make([]byte, a.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := a.gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func (a *AESGCMEncryptor) Decrypt(data []byte) ([]byte, error) {
	nonceSize := a.gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := a.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// ChaCha20Encryptor implements ChaCha20-Poly1305 encryption
type ChaCha20Encryptor struct {
	aead cipher.AEAD
}

// NewChaCha20Encryptor creates a new ChaCha20-Poly1305 encryptor
func NewChaCha20Encryptor(key []byte) (*ChaCha20Encryptor, error) {
	// Ensure key is 32 bytes
	if len(key) != 32 {
		hash := sha256.Sum256(key)
		key = hash[:]
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	return &ChaCha20Encryptor{aead: aead}, nil
}

func (c *ChaCha20Encryptor) Type() EncryptionType { return EncryptionChaCha20 }
func (c *ChaCha20Encryptor) KeySize() int         { return 32 }

func (c *ChaCha20Encryptor) Encrypt(data []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := c.aead.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func (c *ChaCha20Encryptor) Decrypt(data []byte) ([]byte, error) {
	nonceSize := c.aead.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// NoEncryptor implements no encryption (pass-through)
type NoEncryptor struct{}

func (n *NoEncryptor) Type() EncryptionType { return EncryptionNone }
func (n *NoEncryptor) KeySize() int         { return 0 }

func (n *NoEncryptor) Encrypt(data []byte) ([]byte, error) {
	return data, nil
}

func (n *NoEncryptor) Decrypt(data []byte) ([]byte, error) {
	return data, nil
}

// EncryptionStats tracks encryption statistics
type EncryptionStats struct {
	TotalOperations   int64 `json:"total_operations"`
	TotalBytesProcessed int64 `json:"total_bytes_processed"`
	EncryptionTime    int64 `json:"encryption_time_ns"`
	DecryptionTime    int64 `json:"decryption_time_ns"`
	ErrorCount        int64 `json:"error_count"`
}

// UpdateStats updates encryption statistics
func (es *EncryptionStats) UpdateStats(bytesProcessed int, encryptionTime, decryptionTime int64, hasError bool) {
	es.TotalOperations++
	es.TotalBytesProcessed += int64(bytesProcessed)
	es.EncryptionTime += encryptionTime
	es.DecryptionTime += decryptionTime

	if hasError {
		es.ErrorCount++
	}
}

// GetEncryptionEfficiency returns encryption efficiency metrics
func (es *EncryptionStats) GetEncryptionEfficiency() map[string]interface{} {
	avgEncryptionTime := float64(0)
	avgDecryptionTime := float64(0)
	errorRate := float64(0)

	if es.TotalOperations > 0 {
		avgEncryptionTime = float64(es.EncryptionTime) / float64(es.TotalOperations) / 1e6
		avgDecryptionTime = float64(es.DecryptionTime) / float64(es.TotalOperations) / 1e6
		errorRate = float64(es.ErrorCount) / float64(es.TotalOperations) * 100
	}

	return map[string]interface{}{
		"avg_encryption_time_ms":   avgEncryptionTime,
		"avg_decryption_time_ms":   avgDecryptionTime,
		"throughput_mbps":          float64(es.TotalBytesProcessed) / 1024 / 1024 / (float64(es.EncryptionTime + es.DecryptionTime) / 1e9),
		"error_rate_percent":       errorRate,
	}
}
