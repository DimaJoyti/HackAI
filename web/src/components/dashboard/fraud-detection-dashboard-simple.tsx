'use client'

import { useState, useEffect, useCallback } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
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
  PlayIcon,
} from '@heroicons/react/24/outline'

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
  processing_time: number
  metadata?: Record<string, any>
  timestamp: string
}

interface ModelPrediction {
  model_id: string
  model_name: string
  prediction: number
  confidence: number
  process_time: number
  features: Record<string, number>
}

export default function FraudDetectionDashboardSimple() {
  const [activeTab, setActiveTab] = useState('monitor')
  const [isConnected, setIsConnected] = useState(false)
  const [recentDetections, setRecentDetections] = useState<FraudDetectionResponse[]>([])
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
    const healthInterval = setInterval(checkServiceHealth, 30000)
    return () => clearInterval(healthInterval)
  }, [checkServiceHealth])

  const getRiskColor = (riskLevel: string) => {
    const colors = {
      very_low: 'bg-green-100 text-green-800',
      low: 'bg-blue-100 text-blue-800',
      medium: 'bg-yellow-100 text-yellow-800',
      high: 'bg-red-100 text-red-800',
      critical: 'bg-red-600 text-white',
    }
    return colors[riskLevel as keyof typeof colors] || 'bg-gray-100 text-gray-800'
  }

  const getDecisionColor = (decision: string) => {
    const colors = {
      allow: 'bg-green-100 text-green-800',
      challenge: 'bg-yellow-100 text-yellow-800',
      review: 'bg-red-100 text-red-800',
      block: 'bg-red-600 text-white',
    }
    return colors[decision as keyof typeof colors] || 'bg-gray-100 text-gray-800'
  }

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
          <span className={`px-3 py-1 rounded-full text-sm font-medium ${
            isConnected
              ? 'bg-green-100 text-green-800'
              : 'bg-red-100 text-red-800'
          }`}>
            {isConnected ? 'Connected' : 'Disconnected'}
          </span>
          <Button onClick={checkServiceHealth} disabled={isLoading}>
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
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="monitor">Monitor</TabsTrigger>
          <TabsTrigger value="test">Test</TabsTrigger>
          <TabsTrigger value="stats">Statistics</TabsTrigger>
        </TabsList>

        {/* Monitor Tab */}
        <TabsContent value="monitor" className="space-y-6">
          {/* Service Status */}
          <Card>
            <CardHeader>
              <CardTitle>Service Status</CardTitle>
              <CardDescription>
                Current status of the fraud detection service
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center space-x-4">
                {isConnected ? (
                  <CheckCircleIcon className="h-8 w-8 text-green-500" />
                ) : (
                  <ExclamationTriangleIcon className="h-8 w-8 text-red-500" />
                )}
                <div>
                  <div className="text-lg font-semibold">
                    {isConnected ? 'Service Online' : 'Service Offline'}
                  </div>
                  <div className="text-sm text-gray-500">
                    Fraud detection engine status
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

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
                          <span className={`px-2 py-1 rounded text-xs font-medium ${getRiskColor(detection.risk_level)}`}>
                            {detection.risk_level.toUpperCase()}
                          </span>
                          <span className={`px-2 py-1 rounded text-xs font-medium ${getDecisionColor(detection.decision)}`}>
                            {detection.decision.toUpperCase()}
                          </span>
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
                          <strong>Processing Time:</strong> {detection.processing_time}ms
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

        {/* Statistics Tab */}
        <TabsContent value="stats" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>System Statistics</CardTitle>
              <CardDescription>
                Basic fraud detection system statistics
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-8">
                <ShieldCheckIcon className="h-16 w-16 mx-auto text-blue-500 mb-4" />
                <h3 className="text-lg font-semibold mb-2">Fraud Detection Active</h3>
                <p className="text-gray-600">
                  The fraud detection system is running and processing transactions.
                </p>
                <div className="mt-4 text-sm text-gray-500">
                  Service Status: {isConnected ? 'Online' : 'Offline'}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}