'use client'

import { useState, useEffect, useCallback } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import {
  ShieldCheckIcon,
  ShieldExclamationIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
  ChartBarIcon,
  CpuChipIcon,
  EyeIcon,
  PlayIcon,
  StopIcon,
} from '@heroicons/react/24/outline'
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts'

// Types for fraud detection
interface FraudDetectionRequest {
  id: string
  user_id: string
  session_id: string
  transaction_data: {
    amount: number
    currency: string
    merchant: string
    category?: string
  }
  user_context: {
    user_age_days: number
    account_type: string
    previous_transactions?: number
  }
  device_fingerprint: {
    ip_address: string
    user_agent: string
    device_id?: string
  }
  timestamp: string
  priority: number
  metadata?: Record<string, any>
}

interface FraudDetectionResponse {
  request_id: string
  is_fraud: boolean
  fraud_score: number
  confidence: number
  risk_level: string
  decision: string
  reasons: string[]
  model_predictions: ModelPrediction[]
  feature_importance: Record<string, number>
  processing_time: string
  metadata?: Record<string, any>
  timestamp: string
}

interface ModelPrediction {
  model_id: string
  model_name: string
  prediction: number
  confidence: number
  process_time: string
  features: Record<string, number>
}

interface FraudStats {
  total_requests: number
  fraud_detected: number
  false_positives: number
  avg_processing_time: number
  model_accuracy: Record<string, number>
  risk_distribution: Record<string, number>
}

const RISK_COLORS = {
  very_low: '#10b981',
  low: '#3b82f6',
  medium: '#f59e0b',
  high: '#ef4444',
  critical: '#dc2626',
}

const DECISION_COLORS = {
  allow: '#10b981',
  challenge: '#f59e0b',
  review: '#ef4444',
  block: '#dc2626',
}

export default function FraudDetectionDashboard() {
  const [activeTab, setActiveTab] = useState('monitor')
  const [isConnected, setIsConnected] = useState(false)
  const [recentDetections, setRecentDetections] = useState<FraudDetectionResponse[]>([])
  const [fraudStats, setFraudStats] = useState<FraudStats | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Test transaction form state
  const [testTransaction, setTestTransaction] = useState<Partial<FraudDetectionRequest>>({
    user_id: 'user-demo',
    session_id: 'session-demo',
    transaction_data: {
      amount: 100.00,
      currency: 'USD',
      merchant: 'Demo Store',
      category: 'retail',
    },
    user_context: {
      user_age_days: 365,
      account_type: 'verified',
      previous_transactions: 50,
    },
    device_fingerprint: {
      ip_address: '192.168.1.100',
      user_agent: 'Mozilla/5.0 (Demo Browser)',
      device_id: 'device-demo',
    },
    priority: 1,
  })

  // Fetch fraud detection statistics
  const fetchFraudStats = useCallback(async () => {
    try {
      const response = await fetch('http://localhost:8080/api/v1/fraud/stats')
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }
      const data = await response.json()
      setFraudStats(data)
      setIsConnected(true)
      setError(null)
    } catch (err) {
      console.error('Failed to fetch fraud stats:', err)
      setError('Failed to connect to fraud detection service')
      setIsConnected(false)
    }
  }, [])

  // Submit test transaction for fraud detection
  const submitTestTransaction = async () => {
    setIsLoading(true)
    setError(null)

    try {
      const request: FraudDetectionRequest = {
        ...testTransaction as FraudDetectionRequest,
        id: `test-${Date.now()}`,
        timestamp: new Date().toISOString(),
      }

      const response = await fetch('http://localhost:8080/api/v1/fraud/detect', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(request),
      })

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const result: FraudDetectionResponse = await response.json()
      setRecentDetections(prev => [result, ...prev.slice(0, 9)])
      setError(null)
    } catch (err) {
      console.error('Failed to submit test transaction:', err)
      setError('Failed to process fraud detection request')
    } finally {
      setIsLoading(false)
    }
  }

  // Check service health
  const checkServiceHealth = useCallback(async () => {
    try {
      const response = await fetch('http://localhost:8080/api/v1/fraud/health')
      setIsConnected(response.ok)
      if (!response.ok) {
        setError('Fraud detection service is not healthy')
      }
    } catch (err) {
      setIsConnected(false)
      setError('Cannot connect to fraud detection service')
    }
  }, [])

  // Initialize dashboard
  useEffect(() => {
    checkServiceHealth()
    fetchFraudStats()

    // Set up periodic health checks
    const healthInterval = setInterval(checkServiceHealth, 30000)
    const statsInterval = setInterval(fetchFraudStats, 10000)

    return () => {
      clearInterval(healthInterval)
      clearInterval(statsInterval)
    }
  }, [checkServiceHealth, fetchFraudStats])

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            🛡️ Fraud Detection Dashboard
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Real-time fraud detection monitoring and testing
          </p>
        </div>
        <div className="flex items-center space-x-4">
          <Badge variant={isConnected ? 'success' : 'danger'}>
            {isConnected ? 'Connected' : 'Disconnected'}
          </Badge>
          <Button onClick={fetchFraudStats} disabled={isLoading}>
            <ChartBarIcon className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <Alert variant="destructive">
          <ExclamationTriangleIcon className="h-4 w-4" />
          <AlertTitle>Connection Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Main Dashboard Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="monitor">Monitor</TabsTrigger>
          <TabsTrigger value="test">Test</TabsTrigger>
          <TabsTrigger value="analytics">Analytics</TabsTrigger>
          <TabsTrigger value="models">Models</TabsTrigger>
        </TabsList>

        {/* Monitor Tab */}
        <TabsContent value="monitor" className="space-y-6">
          {/* Statistics Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Total Requests</CardTitle>
                <ChartBarIcon className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {fraudStats?.total_requests?.toLocaleString() || '0'}
                </div>
                <p className="text-xs text-muted-foreground">
                  Processed transactions
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Fraud Detected</CardTitle>
                <ShieldExclamationIcon className="h-4 w-4 text-red-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-red-600">
                  {fraudStats?.fraud_detected?.toLocaleString() || '0'}
                </div>
                <p className="text-xs text-muted-foreground">
                  {fraudStats?.total_requests
                    ? `${((fraudStats.fraud_detected / fraudStats.total_requests) * 100).toFixed(2)}% fraud rate`
                    : 'No data'
                  }
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Avg Processing Time</CardTitle>
                <ClockIcon className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {fraudStats?.avg_processing_time?.toFixed(2) || '0'}ms
                </div>
                <p className="text-xs text-muted-foreground">
                  Response latency
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Service Status</CardTitle>
                {isConnected ? (
                  <CheckCircleIcon className="h-4 w-4 text-green-500" />
                ) : (
                  <ExclamationTriangleIcon className="h-4 w-4 text-red-500" />
                )}
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {isConnected ? 'Online' : 'Offline'}
                </div>
                <p className="text-xs text-muted-foreground">
                  Fraud detection engine
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Recent Detections */}
          <Card>
            <CardHeader>
              <CardTitle>Recent Fraud Detections</CardTitle>
              <CardDescription>
                Latest fraud detection results and analysis
              </CardDescription>
            </CardHeader>
            <CardContent>
              {recentDetections.length === 0 ? (
                <div className="text-center py-8 text-gray-500">
                  No recent detections. Submit a test transaction to see results.
                </div>
              ) : (
                <div className="space-y-4">
                  {recentDetections.map((detection, index) => (
                    <div
                      key={detection.request_id}
                      className="border rounded-lg p-4 space-y-3"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <Badge
                            style={{
                              backgroundColor: RISK_COLORS[detection.risk_level as keyof typeof RISK_COLORS] || '#6b7280',
                              color: 'white',
                            }}
                          >
                            {detection.risk_level.toUpperCase()}
                          </Badge>
                          <Badge
                            style={{
                              backgroundColor: DECISION_COLORS[detection.decision as keyof typeof DECISION_COLORS] || '#6b7280',
                              color: 'white',
                            }}
                          >
                            {detection.decision.toUpperCase()}
                          </Badge>
                          <span className="text-sm text-gray-500">
                            {new Date(detection.timestamp).toLocaleString()}
                          </span>
                        </div>
                        <div className="text-right">
                          <div className="text-lg font-semibold">
                            Score: {(detection.fraud_score * 100).toFixed(1)}%
                          </div>
                          <div className="text-sm text-gray-500">
                            Confidence: {(detection.confidence * 100).toFixed(1)}%
                          </div>
                        </div>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                        <div>
                          <strong>Request ID:</strong> {detection.request_id}
                        </div>
                        <div>
                          <strong>Processing Time:</strong> {detection.processing_time}
                        </div>
                      </div>

                      {detection.reasons.length > 0 && (
                        <div>
                          <strong className="text-sm">Reasons:</strong>
                          <ul className="list-disc list-inside text-sm text-gray-600 mt-1">
                            {detection.reasons.map((reason, idx) => (
                              <li key={idx}>{reason}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {detection.model_predictions.length > 0 && (
                        <div>
                          <strong className="text-sm">Model Predictions:</strong>
                          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2 mt-2">
                            {detection.model_predictions.map((pred, idx) => (
                              <div key={idx} className="bg-gray-50 dark:bg-gray-800 rounded p-2 text-xs">
                                <div className="font-medium">{pred.model_name}</div>
                                <div>Score: {(pred.prediction * 100).toFixed(1)}%</div>
                                <div>Confidence: {(pred.confidence * 100).toFixed(1)}%</div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Test Tab */}
        <TabsContent value="test" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Test Fraud Detection</CardTitle>
              <CardDescription>
                Submit a test transaction to evaluate fraud detection performance
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Transaction Data */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">Transaction Data</h3>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <Label htmlFor="amount">Amount</Label>
                      <Input
                        id="amount"
                        type="number"
                        step="0.01"
                        value={testTransaction.transaction_data?.amount || ''}
                        onChange={(e) => setTestTransaction(prev => ({
                          ...prev,
                          transaction_data: {
                            ...prev.transaction_data!,
                            amount: parseFloat(e.target.value) || 0,
                          },
                        }))}
                      />
                    </div>
                    <div>
                      <Label htmlFor="currency">Currency</Label>
                      <Select
                        value={testTransaction.transaction_data?.currency || 'USD'}
                        onValueChange={(value) => setTestTransaction(prev => ({
                          ...prev,
                          transaction_data: {
                            ...prev.transaction_data!,
                            currency: value,
                          },
                        }))}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="USD">USD</SelectItem>
                          <SelectItem value="EUR">EUR</SelectItem>
                          <SelectItem value="GBP">GBP</SelectItem>
                          <SelectItem value="JPY">JPY</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div>
                    <Label htmlFor="merchant">Merchant</Label>
                    <Input
                      id="merchant"
                      value={testTransaction.transaction_data?.merchant || ''}
                      onChange={(e) => setTestTransaction(prev => ({
                        ...prev,
                        transaction_data: {
                          ...prev.transaction_data!,
                          merchant: e.target.value,
                        },
                      }))}
                    />
                  </div>

                  <div>
                    <Label htmlFor="category">Category</Label>
                    <Select
                      value={testTransaction.transaction_data?.category || 'retail'}
                      onValueChange={(value) => setTestTransaction(prev => ({
                        ...prev,
                        transaction_data: {
                          ...prev.transaction_data!,
                          category: value,
                        },
                      }))}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="retail">Retail</SelectItem>
                        <SelectItem value="food_beverage">Food & Beverage</SelectItem>
                        <SelectItem value="electronics">Electronics</SelectItem>
                        <SelectItem value="travel">Travel</SelectItem>
                        <SelectItem value="entertainment">Entertainment</SelectItem>
                        <SelectItem value="other">Other</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                {/* User Context */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold">User Context</h3>

                  <div>
                    <Label htmlFor="user_age_days">Account Age (Days)</Label>
                    <Input
                      id="user_age_days"
                      type="number"
                      value={testTransaction.user_context?.user_age_days || ''}
                      onChange={(e) => setTestTransaction(prev => ({
                        ...prev,
                        user_context: {
                          ...prev.user_context!,
                          user_age_days: parseInt(e.target.value) || 0,
                        },
                      }))}
                    />
                  </div>

                  <div>
                    <Label htmlFor="account_type">Account Type</Label>
                    <Select
                      value={testTransaction.user_context?.account_type || 'verified'}
                      onValueChange={(value) => setTestTransaction(prev => ({
                        ...prev,
                        user_context: {
                          ...prev.user_context!,
                          account_type: value,
                        },
                      }))}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="verified">Verified</SelectItem>
                        <SelectItem value="basic">Basic</SelectItem>
                        <SelectItem value="unverified">Unverified</SelectItem>
                        <SelectItem value="premium">Premium</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div>
                    <Label htmlFor="previous_transactions">Previous Transactions</Label>
                    <Input
                      id="previous_transactions"
                      type="number"
                      value={testTransaction.user_context?.previous_transactions || ''}
                      onChange={(e) => setTestTransaction(prev => ({
                        ...prev,
                        user_context: {
                          ...prev.user_context!,
                          previous_transactions: parseInt(e.target.value) || 0,
                        },
                      }))}
                    />
                  </div>

                  <div>
                    <Label htmlFor="ip_address">IP Address</Label>
                    <Input
                      id="ip_address"
                      value={testTransaction.device_fingerprint?.ip_address || ''}
                      onChange={(e) => setTestTransaction(prev => ({
                        ...prev,
                        device_fingerprint: {
                          ...prev.device_fingerprint!,
                          ip_address: e.target.value,
                        },
                      }))}
                    />
                  </div>

                  <div>
                    <Label htmlFor="priority">Priority</Label>
                    <Select
                      value={testTransaction.priority?.toString() || '1'}
                      onValueChange={(value) => setTestTransaction(prev => ({
                        ...prev,
                        priority: parseInt(value),
                      }))}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="1">Normal (1)</SelectItem>
                        <SelectItem value="2">Medium (2)</SelectItem>
                        <SelectItem value="3">High (3)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </div>

              <div className="flex justify-center">
                <Button
                  onClick={submitTestTransaction}
                  disabled={isLoading || !isConnected}
                  size="lg"
                  className="w-full md:w-auto"
                >
                  {isLoading ? (
                    <>
                      <ClockIcon className="h-4 w-4 mr-2 animate-spin" />
                      Processing...
                    </>
                  ) : (
                    <>
                      <PlayIcon className="h-4 w-4 mr-2" />
                      Submit Test Transaction
                    </>
                  )}
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Quick Test Scenarios */}
          <Card>
            <CardHeader>
              <CardTitle>Quick Test Scenarios</CardTitle>
              <CardDescription>
                Pre-configured test scenarios for different risk levels
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Button
                  variant="outline"
                  onClick={() => setTestTransaction({
                    user_id: 'user-low-risk',
                    session_id: 'session-low-risk',
                    transaction_data: {
                      amount: 50.00,
                      currency: 'USD',
                      merchant: 'Coffee Shop',
                      category: 'food_beverage',
                    },
                    user_context: {
                      user_age_days: 730,
                      account_type: 'verified',
                      previous_transactions: 150,
                    },
                    device_fingerprint: {
                      ip_address: '192.168.1.100',
                      user_agent: 'Mozilla/5.0 (Trusted Browser)',
                    },
                    priority: 1,
                  })}
                  className="h-auto p-4 flex flex-col items-start"
                >
                  <div className="font-semibold text-green-600">Low Risk</div>
                  <div className="text-sm text-left">
                    Small amount, verified user, trusted device
                  </div>
                </Button>

                <Button
                  variant="outline"
                  onClick={() => setTestTransaction({
                    user_id: 'user-medium-risk',
                    session_id: 'session-medium-risk',
                    transaction_data: {
                      amount: 500.00,
                      currency: 'USD',
                      merchant: 'Online Store',
                      category: 'retail',
                    },
                    user_context: {
                      user_age_days: 90,
                      account_type: 'basic',
                      previous_transactions: 25,
                    },
                    device_fingerprint: {
                      ip_address: '203.0.113.1',
                      user_agent: 'Mobile Safari',
                    },
                    priority: 2,
                  })}
                  className="h-auto p-4 flex flex-col items-start"
                >
                  <div className="font-semibold text-yellow-600">Medium Risk</div>
                  <div className="text-sm text-left">
                    Moderate amount, newer user, different location
                  </div>
                </Button>

                <Button
                  variant="outline"
                  onClick={() => setTestTransaction({
                    user_id: 'user-high-risk',
                    session_id: 'session-high-risk',
                    transaction_data: {
                      amount: 5000.00,
                      currency: 'USD',
                      merchant: 'Unknown Merchant',
                      category: 'electronics',
                    },
                    user_context: {
                      user_age_days: 1,
                      account_type: 'unverified',
                      previous_transactions: 0,
                    },
                    device_fingerprint: {
                      ip_address: '10.0.0.1',
                      user_agent: 'Bot/1.0',
                    },
                    priority: 3,
                  })}
                  className="h-auto p-4 flex flex-col items-start"
                >
                  <div className="font-semibold text-red-600">High Risk</div>
                  <div className="text-sm text-left">
                    Large amount, new user, suspicious device
                  </div>
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Analytics Tab */}
        <TabsContent value="analytics" className="space-y-6">
          {fraudStats && (
            <>
              {/* Risk Distribution Chart */}
              <Card>
                <CardHeader>
                  <CardTitle>Risk Level Distribution</CardTitle>
                  <CardDescription>
                    Distribution of transactions by risk level
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={Object.entries(fraudStats.risk_distribution || {}).map(([level, count]) => ({
                            name: level.replace('_', ' ').toUpperCase(),
                            value: count,
                            color: RISK_COLORS[level as keyof typeof RISK_COLORS] || '#6b7280',
                          }))}
                          cx="50%"
                          cy="50%"
                          labelLine={false}
                          label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                          outerRadius={80}
                          fill="#8884d8"
                          dataKey="value"
                        >
                          {Object.entries(fraudStats.risk_distribution || {}).map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={Object.values(RISK_COLORS)[index]} />
                          ))}
                        </Pie>
                        <Tooltip />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </CardContent>
              </Card>

              {/* Model Accuracy Chart */}
              <Card>
                <CardHeader>
                  <CardTitle>Model Performance</CardTitle>
                  <CardDescription>
                    Accuracy comparison across different AI models
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={Object.entries(fraudStats.model_accuracy || {}).map(([model, accuracy]) => ({
                          model: model.replace('_', ' '),
                          accuracy: accuracy * 100,
                        }))}
                      >
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="model" />
                        <YAxis domain={[0, 100]} />
                        <Tooltip formatter={(value) => [`${value}%`, 'Accuracy']} />
                        <Bar dataKey="accuracy" fill="#3b82f6" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </CardContent>
              </Card>
            </>
          )}

          {/* Performance Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Detection Performance</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex justify-between">
                  <span>Total Requests:</span>
                  <span className="font-semibold">
                    {fraudStats?.total_requests?.toLocaleString() || '0'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span>Fraud Detected:</span>
                  <span className="font-semibold text-red-600">
                    {fraudStats?.fraud_detected?.toLocaleString() || '0'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span>False Positives:</span>
                  <span className="font-semibold text-yellow-600">
                    {fraudStats?.false_positives?.toLocaleString() || '0'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span>Fraud Rate:</span>
                  <span className="font-semibold">
                    {fraudStats?.total_requests
                      ? `${((fraudStats.fraud_detected / fraudStats.total_requests) * 100).toFixed(2)}%`
                      : '0%'
                    }
                  </span>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>System Performance</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex justify-between">
                  <span>Avg Processing Time:</span>
                  <span className="font-semibold">
                    {fraudStats?.avg_processing_time?.toFixed(2) || '0'}ms
                  </span>
                </div>
                <div className="flex justify-between">
                  <span>Throughput:</span>
                  <span className="font-semibold">
                    {fraudStats?.avg_processing_time
                      ? `${(1000 / fraudStats.avg_processing_time).toFixed(0)} req/s`
                      : '0 req/s'
                    }
                  </span>
                </div>
                <div className="flex justify-between">
                  <span>Service Status:</span>
                  <Badge variant={isConnected ? 'success' : 'danger'}>
                    {isConnected ? 'Online' : 'Offline'}
                  </Badge>
                </div>
                <div className="flex justify-between">
                  <span>Last Update:</span>
                  <span className="text-sm text-gray-500">
                    {new Date().toLocaleTimeString()}
                  </span>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Models Tab */}
        <TabsContent value="models" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>AI Model Ensemble</CardTitle>
              <CardDescription>
                Individual model performance and ensemble configuration
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {fraudStats?.model_accuracy && Object.entries(fraudStats.model_accuracy).map(([modelId, accuracy]) => (
                  <div key={modelId} className="border rounded-lg p-4">
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="font-semibold">{modelId.replace('_', ' ')}</h3>
                      <Badge variant="outline">
                        {(accuracy * 100).toFixed(1)}% accuracy
                      </Badge>
                    </div>

                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span>Model Type:</span>
                        <span className="capitalize">{modelId.replace('_', ' ')}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Status:</span>
                        <Badge variant="success">Active</Badge>
                      </div>
                      <div className="flex justify-between">
                        <span>Weight:</span>
                        <span>25%</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Last Updated:</span>
                        <span>{new Date().toLocaleDateString()}</span>
                      </div>
                    </div>

                    <div className="mt-4">
                      <div className="flex justify-between text-sm mb-1">
                        <span>Performance</span>
                        <span>{(accuracy * 100).toFixed(1)}%</span>
                      </div>
                      <div className="w-full bg-gray-200 rounded-full h-2">
                        <div
                          className="bg-blue-600 h-2 rounded-full"
                          style={{ width: `${accuracy * 100}%` }}
                        ></div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {(!fraudStats?.model_accuracy || Object.keys(fraudStats.model_accuracy).length === 0) && (
                <div className="text-center py-8 text-gray-500">
                  No model performance data available.
                  Ensure the fraud detection service is running and has processed some requests.
                </div>
              )}
            </CardContent>
          </Card>

          {/* Ensemble Configuration */}
          <Card>
            <CardHeader>
              <CardTitle>Ensemble Configuration</CardTitle>
              <CardDescription>
                Current ensemble settings and voting strategy
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <h3 className="font-semibold">Voting Strategy</h3>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span>Strategy:</span>
                      <Badge variant="outline">Weighted Average</Badge>
                    </div>
                    <div className="flex justify-between">
                      <span>Threshold:</span>
                      <span>0.5</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Min Models:</span>
                      <span>3</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Consensus Required:</span>
                      <span>75%</span>
                    </div>
                  </div>
                </div>

                <div className="space-y-4">
                  <h3 className="font-semibold">Performance Targets</h3>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span>Target Accuracy:</span>
                      <span>95%</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Max Latency:</span>
                      <span>50ms</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Min Throughput:</span>
                      <span>10,000 TPS</span>
                    </div>
                    <div className="flex justify-between">
                      <span>False Positive Rate:</span>
                      <span>&lt; 2%</span>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}