import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';
import { htmlReport } from 'https://raw.githubusercontent.com/benc-uk/k6-reporter/main/dist/bundle.js';
import { textSummary } from 'https://jslib.k6.io/k6-summary/0.0.1/index.js';

// Custom metrics
const errorRate = new Rate('error_rate');
const responseTime = new Trend('response_time');
const requestCount = new Counter('request_count');
const crossCloudLatency = new Trend('cross_cloud_latency');

// Test configuration
const config = {
  aws: {
    baseUrl: __ENV.AWS_BASE_URL || 'https://api-aws.hackai.com',
    region: 'us-west-2'
  },
  gcp: {
    baseUrl: __ENV.GCP_BASE_URL || 'https://api-gcp.hackai.com',
    region: 'us-central1'
  },
  azure: {
    baseUrl: __ENV.AZURE_BASE_URL || 'https://api-azure.hackai.com',
    region: 'eastus'
  }
};

// Test scenarios
export const options = {
  scenarios: {
    // Load test for AWS
    aws_load_test: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '2m', target: 20 },
        { duration: '5m', target: 20 },
        { duration: '2m', target: 40 },
        { duration: '5m', target: 40 },
        { duration: '2m', target: 0 },
      ],
      gracefulRampDown: '30s',
      env: { CLOUD_PROVIDER: 'aws' },
      tags: { cloud: 'aws' },
    },
    
    // Load test for GCP
    gcp_load_test: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '2m', target: 15 },
        { duration: '5m', target: 15 },
        { duration: '2m', target: 30 },
        { duration: '5m', target: 30 },
        { duration: '2m', target: 0 },
      ],
      gracefulRampDown: '30s',
      env: { CLOUD_PROVIDER: 'gcp' },
      tags: { cloud: 'gcp' },
    },
    
    // Load test for Azure
    azure_load_test: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '2m', target: 15 },
        { duration: '5m', target: 15 },
        { duration: '2m', target: 30 },
        { duration: '5m', target: 30 },
        { duration: '2m', target: 0 },
      ],
      gracefulRampDown: '30s',
      env: { CLOUD_PROVIDER: 'azure' },
      tags: { cloud: 'azure' },
    },
    
    // Spike test
    spike_test: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '10s', target: 100 },
        { duration: '1m', target: 100 },
        { duration: '10s', target: 0 },
      ],
      env: { CLOUD_PROVIDER: 'aws' },
      tags: { test_type: 'spike' },
    },
    
    // Cross-cloud connectivity test
    cross_cloud_test: {
      executor: 'constant-vus',
      vus: 10,
      duration: '5m',
      env: { TEST_TYPE: 'cross_cloud' },
      tags: { test_type: 'cross_cloud' },
    },
    
    // Stress test
    stress_test: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '2m', target: 100 },
        { duration: '5m', target: 100 },
        { duration: '2m', target: 200 },
        { duration: '5m', target: 200 },
        { duration: '2m', target: 300 },
        { duration: '5m', target: 300 },
        { duration: '10m', target: 0 },
      ],
      env: { CLOUD_PROVIDER: 'aws' },
      tags: { test_type: 'stress' },
    },
  },
  
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1000'],
    http_req_failed: ['rate<0.05'],
    error_rate: ['rate<0.05'],
    response_time: ['p(95)<500'],
    cross_cloud_latency: ['p(95)<1000'],
  },
};

// Setup function
export function setup() {
  console.log('Starting multi-cloud performance tests...');
  
  // Verify all endpoints are accessible
  const endpoints = [config.aws.baseUrl, config.gcp.baseUrl, config.azure.baseUrl];
  const healthChecks = {};
  
  endpoints.forEach((endpoint, index) => {
    const provider = ['aws', 'gcp', 'azure'][index];
    const response = http.get(`${endpoint}/health`);
    healthChecks[provider] = {
      status: response.status,
      responseTime: response.timings.duration,
      available: response.status === 200
    };
  });
  
  console.log('Health check results:', JSON.stringify(healthChecks, null, 2));
  return { healthChecks, config };
}

// Main test function
export default function(data) {
  const cloudProvider = __ENV.CLOUD_PROVIDER || 'aws';
  const testType = __ENV.TEST_TYPE || 'load';
  
  if (testType === 'cross_cloud') {
    crossCloudConnectivityTest(data);
  } else {
    singleCloudTest(data, cloudProvider);
  }
}

// Single cloud test function
function singleCloudTest(data, cloudProvider) {
  const baseUrl = data.config[cloudProvider].baseUrl;
  
  group(`${cloudProvider.toUpperCase()} API Tests`, function() {
    // Health check
    group('Health Check', function() {
      const response = http.get(`${baseUrl}/health`);
      
      check(response, {
        'health check status is 200': (r) => r.status === 200,
        'health check response time < 200ms': (r) => r.timings.duration < 200,
      });
      
      responseTime.add(response.timings.duration);
      requestCount.add(1);
      errorRate.add(response.status !== 200);
    });
    
    // API endpoint tests
    group('API Endpoints', function() {
      // User authentication
      const authResponse = http.post(`${baseUrl}/api/v1/auth/login`, JSON.stringify({
        email: 'test@hackai.com',
        password: 'testpassword123'
      }), {
        headers: { 'Content-Type': 'application/json' },
      });
      
      check(authResponse, {
        'auth status is 200': (r) => r.status === 200,
        'auth response time < 500ms': (r) => r.timings.duration < 500,
        'auth returns token': (r) => r.json('token') !== undefined,
      });
      
      if (authResponse.status === 200) {
        const token = authResponse.json('token');
        
        // User profile
        const profileResponse = http.get(`${baseUrl}/api/v1/user/profile`, {
          headers: { 'Authorization': `Bearer ${token}` },
        });
        
        check(profileResponse, {
          'profile status is 200': (r) => r.status === 200,
          'profile response time < 300ms': (r) => r.timings.duration < 300,
        });
        
        // Scanner service
        const scanResponse = http.post(`${baseUrl}/api/v1/scan`, JSON.stringify({
          target: 'example.com',
          scanType: 'vulnerability'
        }), {
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          },
        });
        
        check(scanResponse, {
          'scan status is 200 or 202': (r) => r.status === 200 || r.status === 202,
          'scan response time < 1000ms': (r) => r.timings.duration < 1000,
        });
        
        responseTime.add(authResponse.timings.duration);
        responseTime.add(profileResponse.timings.duration);
        responseTime.add(scanResponse.timings.duration);
        
        requestCount.add(3);
        errorRate.add(authResponse.status !== 200);
        errorRate.add(profileResponse.status !== 200);
        errorRate.add(!(scanResponse.status === 200 || scanResponse.status === 202));
      }
    });
    
    // Database operations
    group('Database Operations', function() {
      const dbResponse = http.get(`${baseUrl}/api/v1/stats/database`);
      
      check(dbResponse, {
        'database stats status is 200': (r) => r.status === 200,
        'database response time < 400ms': (r) => r.timings.duration < 400,
      });
      
      responseTime.add(dbResponse.timings.duration);
      requestCount.add(1);
      errorRate.add(dbResponse.status !== 200);
    });
    
    // Cache operations
    group('Cache Operations', function() {
      const cacheResponse = http.get(`${baseUrl}/api/v1/stats/cache`);
      
      check(cacheResponse, {
        'cache stats status is 200': (r) => r.status === 200,
        'cache response time < 200ms': (r) => r.timings.duration < 200,
      });
      
      responseTime.add(cacheResponse.timings.duration);
      requestCount.add(1);
      errorRate.add(cacheResponse.status !== 200);
    });
  });
  
  sleep(1);
}

// Cross-cloud connectivity test
function crossCloudConnectivityTest(data) {
  group('Cross-Cloud Connectivity', function() {
    const clouds = ['aws', 'gcp', 'azure'];
    
    clouds.forEach(sourceCloud => {
      clouds.forEach(targetCloud => {
        if (sourceCloud !== targetCloud) {
          group(`${sourceCloud.toUpperCase()} to ${targetCloud.toUpperCase()}`, function() {
            const sourceUrl = data.config[sourceCloud].baseUrl;
            const targetUrl = data.config[targetCloud].baseUrl;
            
            // Test cross-cloud API call
            const startTime = Date.now();
            const response = http.get(`${sourceUrl}/api/v1/cross-cloud/ping?target=${targetCloud}`);
            const endTime = Date.now();
            
            const latency = endTime - startTime;
            
            check(response, {
              [`cross-cloud ${sourceCloud}->${targetCloud} status is 200`]: (r) => r.status === 200,
              [`cross-cloud ${sourceCloud}->${targetCloud} latency < 2000ms`]: () => latency < 2000,
            });
            
            crossCloudLatency.add(latency, { 
              source: sourceCloud, 
              target: targetCloud 
            });
            requestCount.add(1);
            errorRate.add(response.status !== 200);
          });
        }
      });
    });
  });
  
  sleep(2);
}

// Teardown function
export function teardown(data) {
  console.log('Performance tests completed');
  console.log('Final health check results:', JSON.stringify(data.healthChecks, null, 2));
}

// Custom summary report
export function handleSummary(data) {
  return {
    'performance-test-results.html': htmlReport(data),
    'performance-test-summary.txt': textSummary(data, { indent: ' ', enableColors: true }),
    'performance-test-results.json': JSON.stringify(data, null, 2),
  };
}

// Utility functions for advanced testing scenarios

// WebSocket performance test
export function websocketTest() {
  // WebSocket testing would require additional k6 modules
  console.log('WebSocket performance test placeholder');
}

// GraphQL performance test
export function graphqlTest(baseUrl) {
  const query = `
    query {
      user {
        id
        email
        profile {
          name
          avatar
        }
      }
      scans(limit: 10) {
        id
        target
        status
        createdAt
      }
    }
  `;
  
  const response = http.post(`${baseUrl}/graphql`, JSON.stringify({
    query: query
  }), {
    headers: { 'Content-Type': 'application/json' },
  });
  
  check(response, {
    'GraphQL status is 200': (r) => r.status === 200,
    'GraphQL response time < 500ms': (r) => r.timings.duration < 500,
    'GraphQL no errors': (r) => !r.json('errors'),
  });
  
  return response;
}

// File upload performance test
export function fileUploadTest(baseUrl, token) {
  const file = open('./test-files/sample-upload.txt', 'b');
  
  const response = http.post(`${baseUrl}/api/v1/upload`, {
    file: http.file(file, 'sample-upload.txt', 'text/plain'),
  }, {
    headers: { 'Authorization': `Bearer ${token}` },
  });
  
  check(response, {
    'file upload status is 200': (r) => r.status === 200,
    'file upload response time < 2000ms': (r) => r.timings.duration < 2000,
  });
  
  return response;
}

// Database connection pool test
export function connectionPoolTest(baseUrl) {
  const promises = [];
  
  // Simulate concurrent database operations
  for (let i = 0; i < 50; i++) {
    promises.push(
      http.asyncRequest('GET', `${baseUrl}/api/v1/stats/database`)
    );
  }
  
  const responses = http.batch(promises);
  
  responses.forEach((response, index) => {
    check(response, {
      [`concurrent db request ${index} status is 200`]: (r) => r.status === 200,
      [`concurrent db request ${index} response time < 1000ms`]: (r) => r.timings.duration < 1000,
    });
  });
  
  return responses;
}
