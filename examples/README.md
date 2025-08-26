# 🚀 HackAI Examples

This directory contains comprehensive examples demonstrating various features of the HackAI platform.

## 📋 Available Examples

### 🛡️ **Fraud Detection Demo**
**Location**: `fraud-demo/`
**Description**: Interactive demonstration of the fraud detection system with ensemble AI models.

**Features**:
- Real-time fraud detection with multiple risk scenarios
- Ensemble AI model predictions (Random Forest, XGBoost, Neural Network, Isolation Forest)
- Performance metrics and processing time analysis
- Color-coded risk level visualization

**Prerequisites**:
- Fraud detection service running on `http://localhost:8080`

**Usage**:
```bash
cd fraud-demo
go run main.go
```

### 🤖 **Ollama Complete Example**
**Location**: `olama-complete-example/`
**Description**: Comprehensive demonstration of Ollama integration with HackAI platform.

**Features**:
- Ollama provider setup and configuration
- AI tool integration with presets
- Security scanning with multiple profiles
- Attack orchestration workflows
- Advanced features (embeddings, streaming)

**Prerequisites**:
- Ollama installed and running: `ollama serve`
- Required model pulled: `ollama pull llama2`

**Usage**:
```bash
cd olama-complete-example
go run main.go
```

## 🔧 **Quick Start**

### **Option 1: Interactive Runner**
Use the interactive script to easily select and run examples:
```bash
./run-examples.sh
```

### **Option 2: Direct Execution**
Run examples directly from their respective directories:
```bash
# Fraud Detection Demo
cd fraud-demo && go run main.go

# Ollama Complete Example
cd olama-complete-example && go run main.go
```

## 🛠️ **Setup Instructions**

### **For Fraud Detection Demo**
1. **Start the fraud detection service**:
   ```bash
   cd ../cmd/fraud-service
   go run main.go
   ```

2. **Verify service is running**:
   ```bash
   curl http://localhost:8080/api/v1/fraud/health
   ```

3. **Run the demo**:
   ```bash
   cd fraud-demo
   go run main.go
   ```

### **For Ollama Complete Example**
1. **Install Ollama** (if not already installed):
   ```bash
   # macOS
   brew install ollama

   # Linux
   curl -fsSL https://ollama.ai/install.sh | sh
   ```

2. **Start Ollama service**:
   ```bash
   ollama serve
   ```

3. **Pull required model**:
   ```bash
   ollama pull llama2
   ```

4. **Run the example**:
   ```bash
   cd olama-complete-example
   go run main.go
   ```

## 📊 **Example Outputs**

### **Fraud Detection Demo Output**
```
🛡️  HackAI Fraud Detection Demo
================================

1. Testing: Low Risk Transaction
   ──────────────────────────────────────────────────
   📊 Fraud Score: 0.530
   🎯 Confidence: 0.911
   ⚠️  Risk Level: medium
   🚦 Decision: challenge
   ⏱️  Processing Time: 95ms
   🤖 Models Used: 4
   📝 Reasons:
      • Transaction amount within normal range
      • User account age indicates established user
   🔍 Model Predictions:
      • Neural Network: 0.530 (confidence: 0.911)
      • Random Forest: 0.530 (confidence: 0.911)
      • XGBoost: 0.530 (confidence: 0.911)
      • Isolation Forest: 0.530 (confidence: 0.911)
```

### **Ollama Complete Example Output**
```
🚀 HackAI OLAMA Complete Example
=================================
This example demonstrates:
  • OLAMA provider setup and configuration
  • AI tool integration with presets
  • Security scanning with multiple profiles
  • Attack orchestration workflows
  • Advanced features (embeddings, streaming)

📋 Step 1: Setting up OLAMA Provider
✅ OLAMA provider configured successfully

🔧 Step 2: Creating OLAMA Tool
✅ OLAMA tool created with presets
```

## 🚨 **Troubleshooting**

### **Common Issues**

#### **"Multiple main functions" Error**
**Problem**: Go compiler finds multiple `main` functions in the same directory.
**Solution**: Run examples from their individual directories or use the provided runner script.

#### **Fraud Detection Service Not Available**
**Problem**: `connection refused` when running fraud detection demo.
**Solution**:
1. Start the fraud detection service: `cd ../cmd/fraud-service && go run main.go`
2. Verify it's running: `curl http://localhost:8080/api/v1/fraud/health`

#### **Ollama Model Not Found**
**Problem**: `model llama2 not found` error.
**Solution**:
1. Make sure Ollama is running: `ollama serve`
2. Pull the model: `ollama pull llama2`
3. List available models: `ollama list`

#### **Port Already in Use**
**Problem**: Service fails to start due to port conflict.
**Solution**:
1. Check what's using the port: `lsof -i :8080`
2. Kill the process: `kill -9 <PID>`
3. Or use a different port in the configuration

## 📚 **Additional Resources**

### **Documentation**
- [Fraud Detection API Documentation](../docs/fraud-detection-implementation-summary.md)
- [HackAI Platform Overview](../README.md)
- [Frontend Dashboard Guide](../web/src/components/dashboard/README-fraud-detection.md)

### **External Links**
- [Ollama Models Library](https://ollama.ai/library)
- [Go Documentation](https://golang.org/doc/)
- [HackAI GitHub Repository](https://github.com/DimaJoyti/HackAI)

## 🎯 **Next Steps**

After running the examples, you can:

1. **Explore the Web Dashboard**: Visit `http://localhost:3002/dashboard/fraud`
2. **Test API Endpoints**: Use curl or Postman to test the fraud detection API
3. **Customize Examples**: Modify the examples to test different scenarios
4. **Integrate with Your Code**: Use the examples as templates for your own implementations

---

## 🏆 **Success Indicators**

You'll know the examples are working correctly when you see:

✅ **Fraud Detection Demo**: Colorful output with fraud scores and model predictions
✅ **Ollama Complete Example**: Step-by-step execution with AI provider integration
✅ **No Error Messages**: Clean execution without connection or compilation errors
✅ **Expected Output**: Results matching the sample outputs shown above

Happy coding with HackAI! 🚀