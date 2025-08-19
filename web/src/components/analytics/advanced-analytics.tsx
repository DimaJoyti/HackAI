'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  ChartBarIcon,
  DocumentArrowDownIcon,
  CalendarIcon,
  FunnelIcon,
  ArrowTrendingUpIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
} from '@heroicons/react/24/outline'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { formatDateTime, formatRelativeTime } from '@/lib/utils'
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer, 
  AreaChart, 
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  ScatterChart,
  Scatter,
  ComposedChart
} from 'recharts'

interface AnalyticsData {
  date: string
  threats: number
  vulnerabilities: number
  incidents: number
  resolved: number
  falsePositives: number
  responseTime: number
}

interface Report {
  id: string
  name: string
  type: 'security' | 'compliance' | 'performance' | 'executive'
  status: 'generating' | 'completed' | 'failed' | 'scheduled'
  createdAt: Date
  completedAt?: Date
  size: string
  format: 'pdf' | 'html' | 'csv' | 'json'
  schedule?: string
}

interface Insight {
  id: string
  type: 'trend' | 'anomaly' | 'prediction' | 'recommendation'
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  confidence: number
  impact: string
  createdAt: Date
}

export default function AdvancedAnalytics() {
  const [analyticsData, setAnalyticsData] = useState<AnalyticsData[]>([])
  const [reports, setReports] = useState<Report[]>([])
  const [insights, setInsights] = useState<Insight[]>([])
  const [selectedTimeRange, setSelectedTimeRange] = useState('30d')
  const [selectedMetric, setSelectedMetric] = useState('threats')
  const [isGeneratingReport, setIsGeneratingReport] = useState(false)

  // Generate mock data
  useEffect(() => {
    // Generate analytics data
    const data: AnalyticsData[] = Array.from({ length: 30 }, (_, i) => {
      const date = new Date(Date.now() - (29 - i) * 24 * 60 * 60 * 1000)
      return {
        date: date.toISOString().split('T')[0],
        threats: Math.floor(Math.random() * 50) + 20,
        vulnerabilities: Math.floor(Math.random() * 30) + 10,
        incidents: Math.floor(Math.random() * 15) + 5,
        resolved: Math.floor(Math.random() * 20) + 15,
        falsePositives: Math.floor(Math.random() * 10) + 2,
        responseTime: Math.floor(Math.random() * 60) + 30, // minutes
      }
    })

    // Generate reports
    const reportData: Report[] = [
      {
        id: '1',
        name: 'Monthly Security Report',
        type: 'security',
        status: 'completed',
        createdAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
        completedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000 + 5 * 60 * 1000),
        size: '2.4 MB',
        format: 'pdf',
        schedule: 'Monthly',
      },
      {
        id: '2',
        name: 'Compliance Audit Report',
        type: 'compliance',
        status: 'generating',
        createdAt: new Date(Date.now() - 30 * 60 * 1000),
        size: 'Calculating...',
        format: 'html',
      },
      {
        id: '3',
        name: 'Executive Summary',
        type: 'executive',
        status: 'scheduled',
        createdAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        size: 'Pending',
        format: 'pdf',
        schedule: 'Weekly',
      },
    ]

    // Generate insights
    const insightData: Insight[] = [
      {
        id: '1',
        type: 'trend',
        title: 'Increasing Phishing Attempts',
        description: 'Phishing attempts have increased by 35% over the last 7 days, primarily targeting email accounts.',
        severity: 'high',
        confidence: 92,
        impact: 'High risk to user credentials and data security',
        createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000),
      },
      {
        id: '2',
        type: 'anomaly',
        title: 'Unusual Network Traffic Pattern',
        description: 'Detected abnormal outbound traffic during off-hours, potentially indicating data exfiltration.',
        severity: 'critical',
        confidence: 87,
        impact: 'Potential data breach or malware activity',
        createdAt: new Date(Date.now() - 4 * 60 * 60 * 1000),
      },
      {
        id: '3',
        type: 'prediction',
        title: 'Vulnerability Patch Window',
        description: 'Based on current trends, optimal patching window is predicted for next Tuesday 2-4 AM.',
        severity: 'medium',
        confidence: 78,
        impact: 'Minimal service disruption during maintenance',
        createdAt: new Date(Date.now() - 6 * 60 * 60 * 1000),
      },
      {
        id: '4',
        type: 'recommendation',
        title: 'Enhanced MFA Implementation',
        description: 'Recommend implementing hardware-based MFA for admin accounts to reduce breach risk by 85%.',
        severity: 'medium',
        confidence: 95,
        impact: 'Significant improvement in account security',
        createdAt: new Date(Date.now() - 8 * 60 * 60 * 1000),
      },
    ]

    setAnalyticsData(data)
    setReports(reportData)
    setInsights(insightData)
  }, [])

  const handleGenerateReport = async (type: string) => {
    setIsGeneratingReport(true)
    
    // Simulate report generation
    setTimeout(() => {
      const newReport: Report = {
        id: Math.random().toString(36).substr(2, 9),
        name: `${type.charAt(0).toUpperCase() + type.slice(1)} Report`,
        type: type as any,
        status: 'completed',
        createdAt: new Date(),
        completedAt: new Date(),
        size: `${(Math.random() * 5 + 1).toFixed(1)} MB`,
        format: 'pdf',
      }
      
      setReports(prev => [newReport, ...prev])
      setIsGeneratingReport(false)
    }, 3000)
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'text-green-600'
      case 'generating': return 'text-blue-600'
      case 'failed': return 'text-red-600'
      case 'scheduled': return 'text-yellow-600'
      default: return 'text-gray-600'
    }
  }

  const getInsightIcon = (type: string) => {
    switch (type) {
      case 'trend': return <ArrowTrendingUpIcon className="h-5 w-5" />
      case 'anomaly': return <ExclamationTriangleIcon className="h-5 w-5" />
      case 'prediction': return <ClockIcon className="h-5 w-5" />
      case 'recommendation': return <CheckCircleIcon className="h-5 w-5" />
      default: return <ChartBarIcon className="h-5 w-5" />
    }
  }

  const threatTrendData = analyticsData.map(item => ({
    date: item.date,
    value: item[selectedMetric as keyof AnalyticsData] as number,
  }))

  const severityDistribution = [
    { name: 'Critical', value: 15, color: '#ef4444' },
    { name: 'High', value: 28, color: '#f97316' },
    { name: 'Medium', value: 35, color: '#eab308' },
    { name: 'Low', value: 22, color: '#22c55e' },
  ]

  const responseTimeData = analyticsData.map(item => ({
    date: item.date,
    responseTime: item.responseTime,
    incidents: item.incidents,
  }))

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            Advanced Analytics
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Comprehensive security analytics, insights, and automated reporting
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Select value={selectedTimeRange} onValueChange={setSelectedTimeRange}>
            <SelectTrigger className="w-32">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="7d">7 days</SelectItem>
              <SelectItem value="30d">30 days</SelectItem>
              <SelectItem value="90d">90 days</SelectItem>
              <SelectItem value="1y">1 year</SelectItem>
            </SelectContent>
          </Select>
          <Button onClick={() => handleGenerateReport('security')} disabled={isGeneratingReport}>
            <DocumentArrowDownIcon className="h-4 w-4 mr-2" />
            {isGeneratingReport ? 'Generating...' : 'Generate Report'}
          </Button>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Threats</CardTitle>
            <ExclamationTriangleIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {analyticsData.reduce((sum, item) => sum + item.threats, 0)}
            </div>
            <p className="text-xs text-muted-foreground">
              +12% from last period
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Avg Response Time</CardTitle>
            <ClockIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {Math.round(analyticsData.reduce((sum, item) => sum + item.responseTime, 0) / analyticsData.length)}m
            </div>
            <p className="text-xs text-muted-foreground">
              -8% improvement
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Resolution Rate</CardTitle>
            <CheckCircleIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">94.2%</div>
            <p className="text-xs text-muted-foreground">
              +2.1% from last period
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">False Positives</CardTitle>
            <FunnelIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">5.8%</div>
            <p className="text-xs text-muted-foreground">
              -1.2% improvement
            </p>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="trends" className="space-y-4">
        <TabsList>
          <TabsTrigger value="trends">Trends</TabsTrigger>
          <TabsTrigger value="insights">AI Insights</TabsTrigger>
          <TabsTrigger value="reports">Reports</TabsTrigger>
          <TabsTrigger value="performance">Performance</TabsTrigger>
        </TabsList>

        <TabsContent value="trends" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Threat Trends */}
            <Card>
              <CardHeader>
                <CardTitle>Security Metrics Trends</CardTitle>
                <CardDescription>
                  <Select value={selectedMetric} onValueChange={setSelectedMetric}>
                    <SelectTrigger className="w-48">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="threats">Threats Detected</SelectItem>
                      <SelectItem value="vulnerabilities">Vulnerabilities</SelectItem>
                      <SelectItem value="incidents">Security Incidents</SelectItem>
                      <SelectItem value="resolved">Resolved Issues</SelectItem>
                    </SelectContent>
                  </Select>
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={threatTrendData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis 
                        dataKey="date" 
                        tickFormatter={(value) => new Date(value).toLocaleDateString()}
                      />
                      <YAxis />
                      <Tooltip 
                        labelFormatter={(value) => new Date(value).toLocaleDateString()}
                      />
                      <Area 
                        type="monotone" 
                        dataKey="value" 
                        stroke="#3b82f6" 
                        fill="#3b82f6" 
                        fillOpacity={0.3}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>

            {/* Severity Distribution */}
            <Card>
              <CardHeader>
                <CardTitle>Threat Severity Distribution</CardTitle>
                <CardDescription>
                  Current threat landscape by severity level
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={severityDistribution}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={100}
                        paddingAngle={5}
                        dataKey="value"
                      >
                        {severityDistribution.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="grid grid-cols-2 gap-2 mt-4">
                  {severityDistribution.map((item, index) => (
                    <div key={index} className="flex items-center space-x-2">
                      <div 
                        className="w-3 h-3 rounded-full" 
                        style={{ backgroundColor: item.color }}
                      />
                      <span className="text-sm">{item.name}: {item.value}%</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Response Time Analysis */}
          <Card>
            <CardHeader>
              <CardTitle>Response Time vs Incident Volume</CardTitle>
              <CardDescription>
                Correlation between incident volume and response times
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <ComposedChart data={responseTimeData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis 
                      dataKey="date" 
                      tickFormatter={(value) => new Date(value).toLocaleDateString()}
                    />
                    <YAxis yAxisId="left" />
                    <YAxis yAxisId="right" orientation="right" />
                    <Tooltip 
                      labelFormatter={(value) => new Date(value).toLocaleDateString()}
                    />
                    <Bar yAxisId="left" dataKey="incidents" fill="#8884d8" />
                    <Line yAxisId="right" type="monotone" dataKey="responseTime" stroke="#ff7300" strokeWidth={2} />
                  </ComposedChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="insights" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>AI-Generated Insights</CardTitle>
              <CardDescription>
                Machine learning-powered security insights and recommendations
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {insights.map((insight) => (
                  <motion.div
                    key={insight.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="p-4 border rounded-lg"
                  >
                    <div className="flex items-start space-x-3">
                      <div className={`p-2 rounded-full ${
                        insight.severity === 'critical' ? 'bg-red-100 text-red-600' :
                        insight.severity === 'high' ? 'bg-orange-100 text-orange-600' :
                        insight.severity === 'medium' ? 'bg-yellow-100 text-yellow-600' :
                        'bg-blue-100 text-blue-600'
                      }`}>
                        {getInsightIcon(insight.type)}
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center justify-between mb-2">
                          <h3 className="font-semibold">{insight.title}</h3>
                          <div className="flex items-center space-x-2">
                            <Badge variant={insight.severity as any}>{insight.severity}</Badge>
                            <Badge variant="outline">{insight.confidence}% confidence</Badge>
                          </div>
                        </div>
                        <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                          {insight.description}
                        </p>
                        <div className="flex items-center justify-between text-xs text-gray-500">
                          <span>Impact: {insight.impact}</span>
                          <span>{formatRelativeTime(insight.createdAt)}</span>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="reports" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
            <Button 
              onClick={() => handleGenerateReport('security')} 
              disabled={isGeneratingReport}
              className="h-20 flex-col"
            >
              <DocumentArrowDownIcon className="h-6 w-6 mb-2" />
              Security Report
            </Button>
            <Button 
              onClick={() => handleGenerateReport('compliance')} 
              disabled={isGeneratingReport}
              variant="outline"
              className="h-20 flex-col"
            >
              <DocumentArrowDownIcon className="h-6 w-6 mb-2" />
              Compliance Report
            </Button>
            <Button 
              onClick={() => handleGenerateReport('performance')} 
              disabled={isGeneratingReport}
              variant="outline"
              className="h-20 flex-col"
            >
              <ChartBarIcon className="h-6 w-6 mb-2" />
              Performance Report
            </Button>
            <Button 
              onClick={() => handleGenerateReport('executive')} 
              disabled={isGeneratingReport}
              variant="outline"
              className="h-20 flex-col"
            >
              <DocumentArrowDownIcon className="h-6 w-6 mb-2" />
              Executive Summary
            </Button>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Generated Reports</CardTitle>
              <CardDescription>
                Recent and scheduled security reports
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {reports.map((report) => (
                  <div key={report.id} className="flex items-center justify-between p-3 border rounded-lg">
                    <div className="flex items-center space-x-3">
                      <DocumentArrowDownIcon className="h-5 w-5 text-gray-500" />
                      <div>
                        <p className="font-medium text-sm">{report.name}</p>
                        <div className="flex items-center space-x-2 text-xs text-gray-500">
                          <span>{formatRelativeTime(report.createdAt)}</span>
                          <span>•</span>
                          <span>{report.size}</span>
                          <span>•</span>
                          <span className="uppercase">{report.format}</span>
                          {report.schedule && (
                            <>
                              <span>•</span>
                              <span>{report.schedule}</span>
                            </>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Badge variant={report.type as any}>{report.type}</Badge>
                      <span className={`text-sm ${getStatusColor(report.status)}`}>
                        {report.status}
                      </span>
                      {report.status === 'completed' && (
                        <Button size="sm" variant="outline">
                          Download
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="performance" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>System Performance Metrics</CardTitle>
                <CardDescription>
                  Security system performance over time
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={analyticsData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis 
                        dataKey="date" 
                        tickFormatter={(value) => new Date(value).toLocaleDateString()}
                      />
                      <YAxis />
                      <Tooltip 
                        labelFormatter={(value) => new Date(value).toLocaleDateString()}
                      />
                      <Line type="monotone" dataKey="responseTime" stroke="#8884d8" strokeWidth={2} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Detection Accuracy</CardTitle>
                <CardDescription>
                  True positives vs false positives over time
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={analyticsData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis 
                        dataKey="date" 
                        tickFormatter={(value) => new Date(value).toLocaleDateString()}
                      />
                      <YAxis />
                      <Tooltip 
                        labelFormatter={(value) => new Date(value).toLocaleDateString()}
                      />
                      <Area 
                        type="monotone" 
                        dataKey="resolved" 
                        stackId="1"
                        stroke="#22c55e" 
                        fill="#22c55e" 
                        fillOpacity={0.8}
                      />
                      <Area 
                        type="monotone" 
                        dataKey="falsePositives" 
                        stackId="1"
                        stroke="#ef4444" 
                        fill="#ef4444" 
                        fillOpacity={0.8}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  )
}
