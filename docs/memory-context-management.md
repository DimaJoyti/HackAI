# Memory & Context Management System

## Overview

The Memory & Context Management system provides sophisticated memory capabilities for LLM applications, enabling them to maintain context across conversations, learn from interactions, and build comprehensive knowledge bases.

## Architecture

### Core Components

1. **Episodic Memory** (`pkg/llm/memory/episodic.go`)
   - Stores episodic memories (events, experiences)
   - Tag-based indexing for efficient retrieval
   - Time-range filtering and text search
   - Automatic memory eviction when limits are reached

2. **Semantic Memory** (`pkg/llm/memory/semantic.go`)
   - Fact-based storage using subject-predicate-object triples
   - Confidence scoring for stored facts
   - Multi-index system (subject, predicate, object)
   - Relationship queries and knowledge connections

3. **Context Management** (`pkg/llm/memory/context.go`)
   - Multi-source context retrieval and integration
   - Context compression for fitting within token limits
   - Relevance ranking and smart context selection
   - Conversation summarization capabilities

4. **Memory Consolidation** (`pkg/llm/memory/consolidation.go`)
   - Automatic background consolidation of memories
   - Conversation processing to extract episodes and facts
   - Memory optimization and deduplication
   - Configurable retention policies and archiving

5. **Memory Manager** (`pkg/llm/memory/memory.go`)
   - Unified interface for all memory operations
   - Component integration and configuration management
   - Vector memory for semantic similarity search
   - Conversational memory for session-based history

## Key Features

### Multi-layered Memory Architecture
- **Vector Memory**: Semantic similarity search with embeddings
- **Conversational Memory**: Session-based conversation history
- **Episodic Memory**: Event and experience storage
- **Semantic Memory**: Structured knowledge representation

### Advanced Context Operations
- **Smart Context Retrieval**: Multi-source context aggregation
- **Context Compression**: Intelligent compression to fit context windows
- **Relevance Scoring**: Smart ranking of context relevance
- **Context Integration**: Weighted combination of different sources

### Memory Lifecycle Management
- **Automatic Consolidation**: Background processing of memories
- **Memory Cleanup**: Retention policies and garbage collection
- **Performance Optimization**: Efficient storage and retrieval
- **Analytics & Monitoring**: Comprehensive usage statistics

### Production-Ready Features
- **OpenTelemetry Integration**: Full tracing and metrics
- **Structured Logging**: Comprehensive logging with correlation
- **Error Handling**: Robust error recovery and fallbacks
- **Concurrency Safety**: Thread-safe operations throughout

## Usage Examples

### Basic Memory Operations

```go
// Create memory manager
config := memory.MemoryConfig{
    VectorMemorySize: 1000,
    ConversationTTL:  24 * time.Hour,
}
memoryManager := memory.NewMemoryManager(config, logger)

// Store conversation message
message := memory.Message{
    ID:        "msg1",
    SessionID: "conversation-1",
    Role:      "user",
    Content:   "Hello, I'm interested in AI",
    Timestamp: time.Now(),
}
err := memoryManager.GetConversationalMemory().AddMessage(ctx, "conversation-1", message)
```

### Episodic Memory

```go
// Store an episode
episode := memory.Episode{
    Title:       "AI Course Completion",
    Description: "Successfully completed Introduction to AI course",
    Context:     "Online learning platform, 8-week course",
    Outcome:     "Gained foundational understanding of AI",
    Tags:        []string{"education", "ai", "achievement"},
    Timestamp:   time.Now(),
}
err := memoryManager.GetEpisodicMemory().StoreEpisode(ctx, episode)

// Query episodes
query := memory.EpisodeQuery{
    Query: "machine learning",
    Tags:  []string{"ai", "education"},
    Limit: 10,
}
episodes, err := memoryManager.GetEpisodicMemory().RetrieveEpisodes(ctx, query)
```

### Semantic Memory

```go
// Store a fact
fact := memory.Fact{
    Subject:    "Machine Learning",
    Predicate:  "is_subset_of",
    Object:     "Artificial Intelligence",
    Confidence: 0.95,
    Context:    "Fundamental AI concept",
    Timestamp:  time.Now(),
}
err := memoryManager.GetSemanticMemory().StoreFact(ctx, fact)

// Query facts
facts, err := memoryManager.GetSemanticMemory().RetrieveFacts(ctx, "Machine Learning", 10)
```

### Context Management

```go
// Retrieve relevant context
options := memory.ContextOptions{
    MaxLength:        2000,
    IncludeHistory:   true,
    IncludeEpisodic:  true,
    IncludeSemantic:  true,
    RelevanceFilter:  0.3,
}
contextResult, err := memoryManager.GetContextManager().GetRelevantContext(ctx, "AI projects", options)

// Compress context
compressed, err := memoryManager.GetContextManager().CompressContext(ctx, longText, 500)
```

### Memory Consolidation

```go
// Consolidate conversation
err := memoryManager.GetConsolidator().ConsolidateConversation(ctx, "conversation-1")

// Get consolidation statistics
stats, err := memoryManager.GetConsolidator().GetConsolidationStats(ctx)
```

## Demo Results

The comprehensive demo successfully demonstrated:

1. **✅ Basic Memory Operations**
   - Stored 4 conversation messages
   - Retrieved 4 messages from conversational memory
   - Stored and searched 1 vector embedding

2. **✅ Episodic Memory**
   - Stored 3 episodes with rich metadata
   - Retrieved 1 episode matching "machine learning" query
   - Demonstrated tag-based filtering

3. **✅ Semantic Memory**
   - Stored 4 facts with confidence scores
   - Retrieved 1 fact about "Machine Learning"
   - Showed relationship exploration capabilities

4. **✅ Context Management**
   - Performed context retrieval from multiple sources
   - Demonstrated context compression (381 → 100 chars, 26% ratio)
   - Created conversation summaries

5. **✅ Memory Consolidation**
   - Executed conversation consolidation
   - Performed episode and fact consolidation
   - Generated consolidation statistics

## Integration

The Memory & Context Management system integrates seamlessly with:
- **Chain Management System**: Provides memory context to LLM chains
- **Graph Execution Engine**: Enables memory operations in graph workflows
- **LLM Provider System**: Supplies context for LLM interactions
- **Logging and Observability**: Full tracing and monitoring

## Performance Characteristics

- **Scalability**: Handles large-scale memory operations with efficient indexing
- **Reliability**: Comprehensive error handling and recovery mechanisms
- **Maintainability**: Clean, modular architecture with clear interfaces
- **Extensibility**: Easy to add new memory types and context sources
- **Observability**: Full OpenTelemetry integration for monitoring

## Future Enhancements

- **Vector Similarity Search**: Enhanced semantic search capabilities
- **LLM-powered Summarization**: Intelligent context compression
- **Distributed Memory**: Multi-node memory synchronization
- **Persistent Storage**: Database backends for long-term storage
- **Memory Analytics**: Advanced usage patterns and insights
