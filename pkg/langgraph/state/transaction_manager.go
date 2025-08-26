package state

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dimajoyti/hackai/pkg/logger"
	"github.com/google/uuid"
)

// TransactionManager manages state transactions with ACID properties
type TransactionManager struct {
	store            StateStore
	transactions     map[string]*StateTransaction
	timeout          time.Duration
	logger           *logger.Logger
	mutex            sync.RWMutex
	cleanupTicker    *time.Ticker
	cleanupDone      chan bool
}

// StateTransaction represents a state transaction
type StateTransaction struct {
	ID            string                    `json:"id"`
	Status        TransactionStatus         `json:"status"`
	IsolationLevel IsolationLevel           `json:"isolation_level"`
	Operations    []*TransactionOperation   `json:"operations"`
	Snapshots     map[string]*StateEntry    `json:"snapshots"`
	CreatedAt     time.Time                 `json:"created_at"`
	UpdatedAt     time.Time                 `json:"updated_at"`
	ExpiresAt     time.Time                 `json:"expires_at"`
	CreatedBy     string                    `json:"created_by"`
	Context       map[string]interface{}    `json:"context"`
	Locks         map[string]*TransactionLock `json:"locks"`
	mutex         sync.RWMutex
}

// TransactionStatus represents the status of a transaction
type TransactionStatus string

const (
	TransactionStatusActive    TransactionStatus = "active"
	TransactionStatusCommitted TransactionStatus = "committed"
	TransactionStatusAborted   TransactionStatus = "aborted"
	TransactionStatusExpired   TransactionStatus = "expired"
)

// IsolationLevel defines transaction isolation levels
type IsolationLevel string

const (
	IsolationReadUncommitted IsolationLevel = "read_uncommitted"
	IsolationReadCommitted   IsolationLevel = "read_committed"
	IsolationRepeatableRead  IsolationLevel = "repeatable_read"
	IsolationSerializable    IsolationLevel = "serializable"
)

// TransactionOperation represents an operation within a transaction
type TransactionOperation struct {
	ID        string            `json:"id"`
	Type      OperationType     `json:"type"`
	Key       StateKey          `json:"key"`
	Value     interface{}       `json:"value,omitempty"`
	OldValue  interface{}       `json:"old_value,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
	Applied   bool              `json:"applied"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// OperationType defines types of transaction operations
type OperationType string

const (
	OperationTypeRead   OperationType = "read"
	OperationTypeWrite  OperationType = "write"
	OperationTypeDelete OperationType = "delete"
	OperationTypeUpdate OperationType = "update"
)

// TransactionLock represents a lock held by a transaction
type TransactionLock struct {
	Key         StateKey    `json:"key"`
	Type        LockType    `json:"type"`
	AcquiredAt  time.Time   `json:"acquired_at"`
	ExpiresAt   time.Time   `json:"expires_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// LockType defines types of locks
type LockType string

const (
	LockTypeShared    LockType = "shared"
	LockTypeExclusive LockType = "exclusive"
)

// TransactionStats holds statistics about transactions
type TransactionStats struct {
	ActiveTransactions    int64                  `json:"active_transactions"`
	CommittedTransactions int64                  `json:"committed_transactions"`
	AbortedTransactions   int64                  `json:"aborted_transactions"`
	ExpiredTransactions   int64                  `json:"expired_transactions"`
	AverageOperations     float64                `json:"average_operations"`
	AverageDuration       time.Duration          `json:"average_duration"`
	TotalLocks            int64                  `json:"total_locks"`
	DeadlockCount         int64                  `json:"deadlock_count"`
	Metadata              map[string]interface{} `json:"metadata"`
}

// NewTransactionManager creates a new transaction manager
func NewTransactionManager(store StateStore, timeout time.Duration, logger *logger.Logger) *TransactionManager {
	tm := &TransactionManager{
		store:        store,
		transactions: make(map[string]*StateTransaction),
		timeout:      timeout,
		logger:       logger,
		cleanupDone:  make(chan bool),
	}

	// Start cleanup goroutine
	tm.cleanupTicker = time.NewTicker(time.Minute)
	go tm.cleanupExpiredTransactions()

	return tm
}

// Begin starts a new transaction
func (tm *TransactionManager) Begin(ctx context.Context) (*StateTransaction, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	transaction := &StateTransaction{
		ID:             uuid.New().String(),
		Status:         TransactionStatusActive,
		IsolationLevel: IsolationReadCommitted, // Default isolation level
		Operations:     make([]*TransactionOperation, 0),
		Snapshots:      make(map[string]*StateEntry),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(tm.timeout),
		CreatedBy:      "system", // Could be extracted from context
		Context:        make(map[string]interface{}),
		Locks:          make(map[string]*TransactionLock),
	}

	tm.transactions[transaction.ID] = transaction

	tm.logger.Debug("Transaction started",
		"transaction_id", transaction.ID,
		"isolation_level", transaction.IsolationLevel,
		"expires_at", transaction.ExpiresAt)

	return transaction, nil
}

// Get retrieves state within a transaction
func (tm *TransactionManager) Get(ctx context.Context, txn *StateTransaction, key StateKey) (*StateEntry, error) {
	txn.mutex.Lock()
	defer txn.mutex.Unlock()

	if txn.Status != TransactionStatusActive {
		return nil, fmt.Errorf("transaction %s is not active", txn.ID)
	}

	keyStr := tm.keyToString(key)

	// Check if we have a snapshot for this key
	if snapshot, exists := txn.Snapshots[keyStr]; exists {
		return snapshot, nil
	}

	// Acquire read lock based on isolation level
	if err := tm.acquireLock(txn, key, LockTypeShared); err != nil {
		return nil, fmt.Errorf("failed to acquire read lock: %w", err)
	}

	// Read from store
	entry, err := tm.store.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to read state: %w", err)
	}

	// Create snapshot for repeatable reads
	if txn.IsolationLevel == IsolationRepeatableRead || txn.IsolationLevel == IsolationSerializable {
		txn.Snapshots[keyStr] = entry
	}

	// Record read operation
	operation := &TransactionOperation{
		ID:        uuid.New().String(),
		Type:      OperationTypeRead,
		Key:       key,
		Timestamp: time.Now(),
		Applied:   true,
		Metadata:  make(map[string]interface{}),
	}
	txn.Operations = append(txn.Operations, operation)

	return entry, nil
}

// Set stores state within a transaction
func (tm *TransactionManager) Set(ctx context.Context, txn *StateTransaction, key StateKey, value interface{}) error {
	txn.mutex.Lock()
	defer txn.mutex.Unlock()

	if txn.Status != TransactionStatusActive {
		return fmt.Errorf("transaction %s is not active", txn.ID)
	}

	// Acquire exclusive lock
	if err := tm.acquireLock(txn, key, LockTypeExclusive); err != nil {
		return fmt.Errorf("failed to acquire write lock: %w", err)
	}

	keyStr := tm.keyToString(key)

	// Get current value for rollback
	var oldValue interface{}
	if currentEntry, err := tm.store.Get(ctx, key); err == nil {
		oldValue = currentEntry.Value
	}

	// Create new entry
	entry := &StateEntry{
		Key:         key,
		Value:       value,
		Version:     1, // Will be updated during commit
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Tags:        make(map[string]string),
		Annotations: make(map[string]interface{}),
		Metadata: &StateMetadata{
			Type:        "transactional",
			Encoding:    "json",
			AccessCount: 0,
			Attributes:  make(map[string]interface{}),
		},
	}

	// Store in transaction snapshot
	txn.Snapshots[keyStr] = entry

	// Record write operation
	operation := &TransactionOperation{
		ID:        uuid.New().String(),
		Type:      OperationTypeWrite,
		Key:       key,
		Value:     value,
		OldValue:  oldValue,
		Timestamp: time.Now(),
		Applied:   false, // Will be applied during commit
		Metadata:  make(map[string]interface{}),
	}
	txn.Operations = append(txn.Operations, operation)

	txn.UpdatedAt = time.Now()

	tm.logger.Debug("Transaction write recorded",
		"transaction_id", txn.ID,
		"key", key,
		"operation_id", operation.ID)

	return nil
}

// Delete removes state within a transaction
func (tm *TransactionManager) Delete(ctx context.Context, txn *StateTransaction, key StateKey) error {
	txn.mutex.Lock()
	defer txn.mutex.Unlock()

	if txn.Status != TransactionStatusActive {
		return fmt.Errorf("transaction %s is not active", txn.ID)
	}

	// Acquire exclusive lock
	if err := tm.acquireLock(txn, key, LockTypeExclusive); err != nil {
		return fmt.Errorf("failed to acquire delete lock: %w", err)
	}

	// Get current value for rollback
	var oldValue interface{}
	if currentEntry, err := tm.store.Get(ctx, key); err == nil {
		oldValue = currentEntry.Value
	}

	keyStr := tm.keyToString(key)

	// Mark as deleted in snapshot
	delete(txn.Snapshots, keyStr)

	// Record delete operation
	operation := &TransactionOperation{
		ID:        uuid.New().String(),
		Type:      OperationTypeDelete,
		Key:       key,
		OldValue:  oldValue,
		Timestamp: time.Now(),
		Applied:   false, // Will be applied during commit
		Metadata:  make(map[string]interface{}),
	}
	txn.Operations = append(txn.Operations, operation)

	txn.UpdatedAt = time.Now()

	tm.logger.Debug("Transaction delete recorded",
		"transaction_id", txn.ID,
		"key", key,
		"operation_id", operation.ID)

	return nil
}

// Commit commits a transaction
func (tm *TransactionManager) Commit(ctx context.Context, txn *StateTransaction) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	txn.mutex.Lock()
	defer txn.mutex.Unlock()

	if txn.Status != TransactionStatusActive {
		return fmt.Errorf("transaction %s is not active", txn.ID)
	}

	// Validate transaction before commit
	if err := tm.validateTransaction(ctx, txn); err != nil {
		return fmt.Errorf("transaction validation failed: %w", err)
	}

	// Apply all operations
	for _, operation := range txn.Operations {
		if operation.Applied {
			continue // Skip read operations
		}

		switch operation.Type {
		case OperationTypeWrite:
			entry := txn.Snapshots[tm.keyToString(operation.Key)]
			if err := tm.store.Set(ctx, operation.Key, entry); err != nil {
				// Rollback on failure
				tm.rollbackTransaction(ctx, txn)
				return fmt.Errorf("failed to apply write operation: %w", err)
			}
			operation.Applied = true

		case OperationTypeDelete:
			if err := tm.store.Delete(ctx, operation.Key); err != nil {
				// Rollback on failure
				tm.rollbackTransaction(ctx, txn)
				return fmt.Errorf("failed to apply delete operation: %w", err)
			}
			operation.Applied = true
		}
	}

	// Update transaction status
	txn.Status = TransactionStatusCommitted
	txn.UpdatedAt = time.Now()

	// Release all locks
	tm.releaseAllLocks(txn)

	// Remove from active transactions
	delete(tm.transactions, txn.ID)

	tm.logger.Info("Transaction committed",
		"transaction_id", txn.ID,
		"operations", len(txn.Operations),
		"duration", time.Since(txn.CreatedAt))

	return nil
}

// Rollback rolls back a transaction
func (tm *TransactionManager) Rollback(ctx context.Context, txn *StateTransaction) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	txn.mutex.Lock()
	defer txn.mutex.Unlock()

	if txn.Status != TransactionStatusActive {
		return fmt.Errorf("transaction %s is not active", txn.ID)
	}

	// Rollback applied operations
	tm.rollbackTransaction(ctx, txn)

	// Update transaction status
	txn.Status = TransactionStatusAborted
	txn.UpdatedAt = time.Now()

	// Release all locks
	tm.releaseAllLocks(txn)

	// Remove from active transactions
	delete(tm.transactions, txn.ID)

	tm.logger.Info("Transaction rolled back",
		"transaction_id", txn.ID,
		"operations", len(txn.Operations))

	return nil
}

// GetStats returns transaction statistics
func (tm *TransactionManager) GetStats() *TransactionStats {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	stats := &TransactionStats{
		Metadata: make(map[string]interface{}),
	}

	var totalOperations int64
	var totalLocks int64

	for _, txn := range tm.transactions {
		if txn.Status == TransactionStatusActive {
			stats.ActiveTransactions++
		}
		totalOperations += int64(len(txn.Operations))
		totalLocks += int64(len(txn.Locks))
	}

	stats.TotalLocks = totalLocks

	if stats.ActiveTransactions > 0 {
		stats.AverageOperations = float64(totalOperations) / float64(stats.ActiveTransactions)
	}

	return stats
}

// Close closes the transaction manager
func (tm *TransactionManager) Close() error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	// Stop cleanup ticker
	if tm.cleanupTicker != nil {
		tm.cleanupTicker.Stop()
		close(tm.cleanupDone)
	}

	// Rollback all active transactions
	for _, txn := range tm.transactions {
		if txn.Status == TransactionStatusActive {
			tm.rollbackTransaction(context.Background(), txn)
		}
	}

	tm.logger.Info("Transaction manager closed")
	return nil
}

// Helper methods

func (tm *TransactionManager) keyToString(key StateKey) string {
	return fmt.Sprintf("%s:%s:%s:%s", key.Namespace, key.GraphID, key.NodeID, key.Key)
}

func (tm *TransactionManager) acquireLock(txn *StateTransaction, key StateKey, lockType LockType) error {
	keyStr := tm.keyToString(key)

	// Check if we already have a lock
	if existingLock, exists := txn.Locks[keyStr]; exists {
		// Upgrade lock if necessary
		if existingLock.Type == LockTypeShared && lockType == LockTypeExclusive {
			existingLock.Type = LockTypeExclusive
			existingLock.AcquiredAt = time.Now()
		}
		return nil
	}

	// Create new lock
	lock := &TransactionLock{
		Key:        key,
		Type:       lockType,
		AcquiredAt: time.Now(),
		ExpiresAt:  time.Now().Add(tm.timeout),
		Metadata:   make(map[string]interface{}),
	}

	txn.Locks[keyStr] = lock
	return nil
}

func (tm *TransactionManager) releaseAllLocks(txn *StateTransaction) {
	for keyStr := range txn.Locks {
		delete(txn.Locks, keyStr)
	}
}

func (tm *TransactionManager) validateTransaction(ctx context.Context, txn *StateTransaction) error {
	// Check for conflicts with other transactions
	// This is a simplified implementation
	// In production, implement proper conflict detection

	// Check if transaction has expired
	if time.Now().After(txn.ExpiresAt) {
		return fmt.Errorf("transaction has expired")
	}

	return nil
}

func (tm *TransactionManager) rollbackTransaction(ctx context.Context, txn *StateTransaction) {
	// Rollback applied operations in reverse order
	for i := len(txn.Operations) - 1; i >= 0; i-- {
		operation := txn.Operations[i]
		if !operation.Applied {
			continue
		}

		switch operation.Type {
		case OperationTypeWrite:
			if operation.OldValue != nil {
				// Restore old value
				entry := &StateEntry{
					Key:   operation.Key,
					Value: operation.OldValue,
				}
				tm.store.Set(ctx, operation.Key, entry)
			} else {
				// Delete if it was a new key
				tm.store.Delete(ctx, operation.Key)
			}

		case OperationTypeDelete:
			if operation.OldValue != nil {
				// Restore deleted value
				entry := &StateEntry{
					Key:   operation.Key,
					Value: operation.OldValue,
				}
				tm.store.Set(ctx, operation.Key, entry)
			}
		}
	}
}

func (tm *TransactionManager) cleanupExpiredTransactions() {
	for {
		select {
		case <-tm.cleanupTicker.C:
			tm.mutex.Lock()
			now := time.Now()
			
			for txnID, txn := range tm.transactions {
				if txn.Status == TransactionStatusActive && now.After(txn.ExpiresAt) {
					txn.Status = TransactionStatusExpired
					tm.releaseAllLocks(txn)
					delete(tm.transactions, txnID)
					
					tm.logger.Warn("Transaction expired",
						"transaction_id", txnID,
						"created_at", txn.CreatedAt)
				}
			}
			tm.mutex.Unlock()

		case <-tm.cleanupDone:
			return
		}
	}
}
