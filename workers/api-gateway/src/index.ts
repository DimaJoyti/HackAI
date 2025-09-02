/**
 * HackAI API Gateway - Cloudflare Worker
 * Main entry point for the API Gateway service
 */

export interface Env {
  HACKAI_DB: D1Database;
  LOGS_BUCKET: R2Bucket;
  UPLOADS_BUCKET: R2Bucket;
  NEXT_CACHE_KV: KVNamespace;
  JWT_SECRET: string;
  OPENAI_API_KEY: string;
}

interface APIResponse {
  success: boolean;
  data?: any;
  error?: string;
  timestamp: string;
}

// CORS headers for all responses
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

// Helper function to create standardized API responses
function createResponse(data: any, status: number = 200): Response {
  const response: APIResponse = {
    success: status < 400,
    data: status < 400 ? data : undefined,
    error: status >= 400 ? data : undefined,
    timestamp: new Date().toISOString(),
  };

  return new Response(JSON.stringify(response), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders,
    },
  });
}

// Authentication middleware
async function authenticate(request: Request, env: Env): Promise<{ userId?: number; error?: string }> {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return { error: 'Missing or invalid authorization header' };
  }

  const token = authHeader.substring(7);
  
  try {
    // Simple JWT verification (in production, use proper JWT library)
    const payload = JSON.parse(atob(token.split('.')[1]));
    
    if (payload.exp < Date.now() / 1000) {
      return { error: 'Token expired' };
    }

    return { userId: payload.userId };
  } catch (error) {
    return { error: 'Invalid token' };
  }
}

// Health check endpoint
async function handleHealth(): Promise<Response> {
  return createResponse({
    status: 'healthy',
    service: 'hackai-api-gateway',
    version: '1.0.0',
    uptime: Date.now(),
  });
}

// User management endpoints
async function handleUsers(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const method = request.method;

  switch (method) {
    case 'GET':
      return handleGetUsers(env);
    case 'POST':
      return handleCreateUser(request, env);
    default:
      return createResponse('Method not allowed', 405);
  }
}

async function handleGetUsers(env: Env): Promise<Response> {
  try {
    const result = await env.HACKAI_DB.prepare(
      'SELECT id, email, username, role, created_at FROM users ORDER BY created_at DESC LIMIT 50'
    ).all();

    return createResponse(result.results);
  } catch (error) {
    console.error('Error fetching users:', error);
    return createResponse('Internal server error', 500);
  }
}

async function handleCreateUser(request: Request, env: Env): Promise<Response> {
  try {
    const body = await request.json() as any;
    const { email, username, password, role = 'user' } = body;

    if (!email || !username || !password) {
      return createResponse('Missing required fields', 400);
    }

    // Simple password hashing (in production, use proper bcrypt)
    const passwordHash = btoa(password);

    const result = await env.HACKAI_DB.prepare(
      'INSERT INTO users (email, username, password_hash, role) VALUES (?, ?, ?, ?)'
    ).bind(email, username, passwordHash, role).run();

    if (result.success) {
      return createResponse({ id: result.meta.last_row_id, email, username, role }, 201);
    } else {
      return createResponse('Failed to create user', 500);
    }
  } catch (error) {
    console.error('Error creating user:', error);
    return createResponse('Internal server error', 500);
  }
}

// Security scan endpoints
async function handleScans(request: Request, env: Env): Promise<Response> {
  const auth = await authenticate(request, env);
  if (auth.error) {
    return createResponse(auth.error, 401);
  }

  const url = new URL(request.url);
  const method = request.method;

  switch (method) {
    case 'GET':
      return handleGetScans(auth.userId!, env);
    case 'POST':
      return handleCreateScan(request, auth.userId!, env);
    default:
      return createResponse('Method not allowed', 405);
  }
}

async function handleGetScans(userId: number, env: Env): Promise<Response> {
  try {
    const result = await env.HACKAI_DB.prepare(
      'SELECT * FROM security_scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 20'
    ).bind(userId).all();

    return createResponse(result.results);
  } catch (error) {
    console.error('Error fetching scans:', error);
    return createResponse('Internal server error', 500);
  }
}

async function handleCreateScan(request: Request, userId: number, env: Env): Promise<Response> {
  try {
    const body = await request.json() as any;
    const { scan_type, target_url } = body;

    if (!scan_type || !target_url) {
      return createResponse('Missing required fields', 400);
    }

    const result = await env.HACKAI_DB.prepare(
      'INSERT INTO security_scans (user_id, scan_type, target_url, status) VALUES (?, ?, ?, ?)'
    ).bind(userId, scan_type, target_url, 'pending').run();

    if (result.success) {
      // Log the scan creation
      await env.LOGS_BUCKET.put(
        `scans/${Date.now()}-${result.meta.last_row_id}.json`,
        JSON.stringify({
          scanId: result.meta.last_row_id,
          userId,
          scanType: scan_type,
          targetUrl: target_url,
          timestamp: new Date().toISOString(),
        })
      );

      return createResponse({
        id: result.meta.last_row_id,
        scan_type,
        target_url,
        status: 'pending',
      }, 201);
    } else {
      return createResponse('Failed to create scan', 500);
    }
  } catch (error) {
    console.error('Error creating scan:', error);
    return createResponse('Internal server error', 500);
  }
}

// Main request handler
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Handle CORS preflight requests
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // Route requests to appropriate handlers
      if (path === '/health') {
        return handleHealth();
      } else if (path.startsWith('/api/users')) {
        return handleUsers(request, env);
      } else if (path.startsWith('/api/scans')) {
        return handleScans(request, env);
      } else {
        return createResponse('Not found', 404);
      }
    } catch (error) {
      console.error('Unhandled error:', error);
      return createResponse('Internal server error', 500);
    }
  },
};
