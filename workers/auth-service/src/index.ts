/**
 * HackAI Authentication Service - Cloudflare Worker
 * Handles user authentication, registration, and JWT token management
 */

export interface Env {
  HACKAI_DB: D1Database;
  LOGS_BUCKET: R2Bucket;
  AUTH_KV: KVNamespace;
  JWT_SECRET: string;
  BCRYPT_ROUNDS: string;
}

interface AuthResponse {
  success: boolean;
  data?: any;
  error?: string;
  timestamp: string;
}

interface LoginRequest {
  email: string;
  password: string;
}

interface RegisterRequest {
  email: string;
  username: string;
  password: string;
  role?: string;
}

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function createResponse(data: any, status: number = 200): Response {
  const response: AuthResponse = {
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

// Simple password hashing (in production, use proper bcrypt)
async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
  const passwordHash = await hashPassword(password);
  return passwordHash === hash;
}

// JWT token creation
async function createJWT(payload: any, secret: string): Promise<string> {
  const header = {
    alg: 'HS256',
    typ: 'JWT'
  };

  const now = Math.floor(Date.now() / 1000);
  const jwtPayload = {
    ...payload,
    iat: now,
    exp: now + (24 * 60 * 60), // 24 hours
  };

  const encodedHeader = btoa(JSON.stringify(header));
  const encodedPayload = btoa(JSON.stringify(jwtPayload));
  
  const signatureInput = `${encodedHeader}.${encodedPayload}`;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(signatureInput));
  const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)));
  
  return `${signatureInput}.${encodedSignature}`;
}

// User registration
async function handleRegister(request: Request, env: Env): Promise<Response> {
  try {
    const body = await request.json() as RegisterRequest;
    const { email, username, password, role = 'user' } = body;

    if (!email || !username || !password) {
      return createResponse('Missing required fields', 400);
    }

    // Check if user already exists
    const existingUser = await env.HACKAI_DB.prepare(
      'SELECT id FROM users WHERE email = ? OR username = ?'
    ).bind(email, username).first();

    if (existingUser) {
      return createResponse('User already exists', 409);
    }

    // Hash password
    const passwordHash = await hashPassword(password);

    // Create user
    const result = await env.HACKAI_DB.prepare(
      'INSERT INTO users (email, username, password_hash, role) VALUES (?, ?, ?, ?)'
    ).bind(email, username, passwordHash, role).run();

    if (result.success) {
      // Log registration
      await env.LOGS_BUCKET.put(
        `auth/registrations/${Date.now()}-${result.meta.last_row_id}.json`,
        JSON.stringify({
          userId: result.meta.last_row_id,
          email,
          username,
          role,
          timestamp: new Date().toISOString(),
        })
      );

      // Create JWT token
      const token = await createJWT({
        userId: result.meta.last_row_id,
        email,
        username,
        role,
      }, env.JWT_SECRET);

      return createResponse({
        user: {
          id: result.meta.last_row_id,
          email,
          username,
          role,
        },
        token,
      }, 201);
    } else {
      return createResponse('Failed to create user', 500);
    }
  } catch (error) {
    console.error('Registration error:', error);
    return createResponse('Internal server error', 500);
  }
}

// User login
async function handleLogin(request: Request, env: Env): Promise<Response> {
  try {
    const body = await request.json() as LoginRequest;
    const { email, password } = body;

    if (!email || !password) {
      return createResponse('Missing email or password', 400);
    }

    // Find user
    const user = await env.HACKAI_DB.prepare(
      'SELECT id, email, username, password_hash, role FROM users WHERE email = ?'
    ).bind(email).first() as any;

    if (!user) {
      return createResponse('Invalid credentials', 401);
    }

    // Verify password
    const isValidPassword = await verifyPassword(password, user.password_hash);
    if (!isValidPassword) {
      return createResponse('Invalid credentials', 401);
    }

    // Create JWT token
    const token = await createJWT({
      userId: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
    }, env.JWT_SECRET);

    // Store session in KV
    await env.AUTH_KV.put(`session:${user.id}`, token, { expirationTtl: 86400 }); // 24 hours

    // Log login
    await env.LOGS_BUCKET.put(
      `auth/logins/${Date.now()}-${user.id}.json`,
      JSON.stringify({
        userId: user.id,
        email: user.email,
        timestamp: new Date().toISOString(),
      })
    );

    return createResponse({
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role,
      },
      token,
    });
  } catch (error) {
    console.error('Login error:', error);
    return createResponse('Internal server error', 500);
  }
}

// Token verification
async function handleVerify(request: Request, env: Env): Promise<Response> {
  try {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return createResponse('Missing or invalid authorization header', 401);
    }

    const token = authHeader.substring(7);
    
    // Simple JWT verification
    const payload = JSON.parse(atob(token.split('.')[1]));
    
    if (payload.exp < Date.now() / 1000) {
      return createResponse('Token expired', 401);
    }

    // Verify session exists in KV
    const session = await env.AUTH_KV.get(`session:${payload.userId}`);
    if (!session) {
      return createResponse('Session not found', 401);
    }

    return createResponse({
      valid: true,
      user: {
        id: payload.userId,
        email: payload.email,
        username: payload.username,
        role: payload.role,
      },
    });
  } catch (error) {
    console.error('Token verification error:', error);
    return createResponse('Invalid token', 401);
  }
}

// Logout
async function handleLogout(request: Request, env: Env): Promise<Response> {
  try {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return createResponse('Missing authorization header', 401);
    }

    const token = authHeader.substring(7);
    const payload = JSON.parse(atob(token.split('.')[1]));
    
    // Remove session from KV
    await env.AUTH_KV.delete(`session:${payload.userId}`);

    return createResponse({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    return createResponse('Internal server error', 500);
  }
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      switch (path) {
        case '/auth/register':
          return request.method === 'POST' ? handleRegister(request, env) : createResponse('Method not allowed', 405);
        case '/auth/login':
          return request.method === 'POST' ? handleLogin(request, env) : createResponse('Method not allowed', 405);
        case '/auth/verify':
          return request.method === 'GET' ? handleVerify(request, env) : createResponse('Method not allowed', 405);
        case '/auth/logout':
          return request.method === 'POST' ? handleLogout(request, env) : createResponse('Method not allowed', 405);
        default:
          return createResponse('Not found', 404);
      }
    } catch (error) {
      console.error('Unhandled error:', error);
      return createResponse('Internal server error', 500);
    }
  },
};
