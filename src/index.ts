import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { logger } from 'hono/logger'
import { secureHeaders } from 'hono/secure-headers'
import { setCookie, getCookie } from 'hono/cookie'
import JWTAuth from './auth'

const app = new Hono<{ Bindings: CloudflareBindings }>()
const auth = new JWTAuth('mysecret')


// Middleware
app.use('*', logger())
app.use('*', secureHeaders())
app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400,
  credentials: true,
}))


async function validateToken(token: string) {
  try {
    const payload = await auth.verify(token)
    return payload
  } catch (error) {
    return null
  }
}

// Home page with HTML content
app.get('/', (c) => {
  const token = getCookie(c, 'cf-jwt-token') || c.header('Authorization') || ''

  let payload;
  try {
    payload = validateToken(token)
  } catch (err) {
    payload = null
  }

  return c.html(`
<!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>JWT Auth with Cloudflare Workers & Hono</title>
      <script src="https://cdn.tailwindcss.com"></script>
      <style>
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(-10px); }
          to { opacity: 1; transform: translateY(0); }
        }
        .animate-fadeIn {
          animation: fadeIn 0.5s ease-out forwards;
        }
      </style>
    </head>
    <body class="bg-gray-100 min-h-screen">
      <div class="container mx-auto px-4 py-8">
        <header class="mb-10 text-center">
          <h1 class="text-4xl font-bold text-indigo-700 mb-2">JWT Authentication</h1>
          <h2 class="text-xl text-gray-600">with Cloudflare Workers & Hono</h2>
          <p class="mt-2 text-gray-500">by Chapi Menge</p>
        </header>
        
        <div class="max-w-md mx-auto bg-white rounded-lg shadow-lg overflow-hidden">
          <div class="px-6 py-8">
            <div class="mb-6" id="login-section">
              <h3 class="text-xl font-semibold text-gray-800 mb-4">Login</h3>
              <form id="login-form" class="space-y-4">
                <div>
                  <label for="username" class="block text-sm font-medium text-gray-700 mb-1">Username</label>
                  <input type="text" id="username" name="username" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500" required>
                </div>
                <div>
                  <label for="password" class="block text-sm font-medium text-gray-700 mb-1">Password</label>
                  <input type="password" id="password" name="password" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500" required>
                  <p class="text-xs text-gray-500 mt-1">*Any username/password will work for demo purposes</p>
                </div>
                <button type="submit" class="w-full bg-indigo-600 text-white py-2 px-4 rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 transition duration-200">Login</button>
              </form>
            </div>
            
            <div id="user-info" class="${payload ? 'block' : 'hidden'}">
              <h3 class="text-xl font-semibold text-gray-800 mb-4">User Information</h3>
              <div class="bg-gray-50 p-4 rounded-md">
                <pre id="user-data" class="text-sm text-gray-800 overflow-auto"></pre>
              </div>
              <div class="mt-4">
                <button id="logout-btn" class="w-full bg-red-600 text-white py-2 px-4 rounded-md hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 transition duration-200">Logout</button>
              </div>
            </div>
          </div>
          
          <div class="bg-gray-50 px-6 py-4">
            <div id="token-section" class="hidden">
              <h4 class="text-sm font-medium text-gray-700 mb-2">JWT Token</h4>
              <div class="bg-gray-100 p-2 rounded text-xs text-gray-600 font-mono break-all">
                <code id="token-display"></code>
              </div>
            </div>
          </div>
        </div>
        
        <div class="max-w-md mx-auto mt-8">
          <div id="status-message" class="hidden rounded-md p-4 mb-4"></div>
          
          <div class="mt-10 text-center text-sm text-gray-500">
            <p>This demo showcases JWT authentication in Cloudflare Workers using Hono.</p>
            <p class="mt-1">Check out the <a href="https://github.com/chapimenge3/cloudflare-jwt-auth" class="text-indigo-600 hover:underline">GitHub repository</a> for more information.</p>
          </div>
        </div>
      </div>
      
      <script>
        document.addEventListener('DOMContentLoaded', function() {
          const loginForm = document.getElementById('login-form');
          const loginSection = document.getElementById('login-section');
          const userInfo = document.getElementById('user-info');
          const userData = document.getElementById('user-data');
          const logoutBtn = document.getElementById('logout-btn');
          const tokenSection = document.getElementById('token-section');
          const tokenDisplay = document.getElementById('token-display');
          const statusMessage = document.getElementById('status-message');
          
          // Initialize the session state
          initializeSession();
          
          // Initialize session and check if user is already logged in
          function initializeSession() {
            // Check for saved token in localStorage
            const savedToken = localStorage.getItem('jwt-token');
            // Check for token in cookies
            const cookieToken = getCookie('cf-jwt-token');
            // Use saved token, cookie token, or null in that order of preference
            const token = savedToken || cookieToken;
            
            if (token) {
              // Display token if available
              tokenDisplay.textContent = token;
              tokenSection.classList.remove('hidden');
              // Fetch user info using the token
              fetchUserInfo(token);
            }
          }
          
          loginForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            try {
              const response = await fetch('/login', {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password }),
                credentials: 'include' // Important: include cookies in the request
              });
              
              const data = await response.json();
              
              if (response.ok) {
                // Save token to localStorage for persistence
                if (data.token) {
                  localStorage.setItem('jwt-token', data.token);
                  tokenDisplay.textContent = data.token;
                  tokenSection.classList.remove('hidden');
                }
                
                showStatusMessage('Login successful!', 'success');
                fetchUserInfo(data.token);
              } else {
                showStatusMessage(data.message || 'Login failed!', 'error');
              }
            } catch (error) {
              showStatusMessage('An error occurred. Please try again.', 'error');
              console.error('Error:', error);
            }
          });
          
          logoutBtn.addEventListener('click', async function() {
            try {
              // Call the logout endpoint
              await fetch('/logout', {
                method: 'POST',
                credentials: 'include' // Include cookies
              });
              
              // Clear localStorage
              localStorage.removeItem('jwt-token');
              
              // Reset UI
              loginSection.classList.remove('hidden');
              userInfo.classList.add('hidden');
              tokenSection.classList.add('hidden');
              showStatusMessage('You have been logged out.', 'info');
            } catch (error) {
              console.error('Error during logout:', error);
              
              // Even if the server request fails, clear local data
              localStorage.removeItem('jwt-token');
              document.cookie = 'cf-jwt-token=; Max-Age=0; path=/; samesite=lax;';
              
              loginSection.classList.remove('hidden');
              userInfo.classList.add('hidden');
              tokenSection.classList.add('hidden');
            }
          });
          
          async function fetchUserInfo(token) {
            if (!token) return;
            
            try {
              const response = await fetch('/me', {
                headers: {
                  'Authorization': token
                },
                credentials: 'include' // Include cookies in the request
              });
              
              if (response.ok) {
                const data = await response.json();
                userData.textContent = JSON.stringify(data, null, 2);
                loginSection.classList.add('hidden');
                userInfo.classList.remove('hidden');
              } else {
                // Token invalid, clear storage and reset UI
                localStorage.removeItem('jwt-token');
                document.cookie = 'cf-jwt-token=; Max-Age=0; path=/; samesite=lax;';
                loginSection.classList.remove('hidden');
                userInfo.classList.add('hidden');
                tokenSection.classList.add('hidden');
                
                if (response.status === 401) {
                  showStatusMessage('Your session has expired. Please login again.', 'info');
                }
              }
            } catch (error) {
              console.error('Error fetching user info:', error);
              showStatusMessage('Could not retrieve user data. Please try again.', 'error');
            }
          }
          
          function showStatusMessage(message, type) {
            statusMessage.textContent = message;
            statusMessage.className = 'rounded-md p-4 mb-4 animate-fadeIn';
            
            if (type === 'success') {
              statusMessage.classList.add('bg-green-50', 'text-green-800');
            } else if (type === 'error') {
              statusMessage.classList.add('bg-red-50', 'text-red-800');
            } else if (type === 'info') {
              statusMessage.classList.add('bg-blue-50', 'text-blue-800');
            }
            
            statusMessage.classList.remove('hidden');
            
            // Auto-hide after 5 seconds
            setTimeout(() => {
              statusMessage.classList.add('hidden');
            }, 5000);
          }
          
          function getCookie(name) {
            const value = "; " + document.cookie;
            const parts = value.split("; " + name + "=");
            if (parts.length === 2) return parts.pop().split(";").shift();
            return null;
          }
          
          // Handle beforeunload to ensure session persistence
          window.addEventListener('beforeunload', function() {
            // Nothing needed here anymore as we're using localStorage
            // which persists across page refreshes automatically
          });
        });
      </script>
    </body>
    </html>
  `)
})

// Login endpoint
app.post('/login', async (c) => {
  try {
    const { username, password } = await c.req.json()

    // In a real application, you would validate credentials here
    // For demo purposes, we accept any username/password

    // Create a token with user information
    const token = await auth.sign({
      id: 1,
      username,
      role: 'user',
      loginTime: new Date().toISOString()
    }, { expiresIn: '1h' })

    // Set cookie with token
    setCookie(c, 'cf-jwt-token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: 60 * 60, // 1 hour
      path: '/'
    })

    return c.json({ token, success: true })
  } catch (error) {
    return c.json({ message: 'Invalid request', success: false }, 400)
  }
})

// Protected endpoint to get user info from token
app.get('/me', async (c) => {
  // Get the token from Authorization header or from cookie
  const authHeader = c.req.header('Authorization')
  // const cookieToken = c.req.cookie.get('cf-jwt-token')
  const token = authHeader || getCookie(c, 'cf-jwt-token') || ''

  if (!token) {
    return c.json({ message: 'Unauthorized', success: false }, 401)
  }

  try {
    const payload = await auth.verify(token)

    return c.json({
      ...payload,
      success: true
    })
  } catch (err) {
    return c.json({
      message: 'Invalid or expired token',
      success: false
    }, 401)
  }
})

// Refresh token endpoint
app.post('/refresh', async (c) => {
  const token = getCookie(c, 'cf-jwt-token') || c.header('Authorization') || ''

  if (!token) {
    return c.json({ message: 'No token provided', success: false }, 401)
  }

  try {
    const payload = await validateToken(token)
    if (!payload) {
      return c.json({ message: 'Invalid token', success: false }, 401)
    }

    // Remove exp and iat from the payload
    const { exp, iat, ...userData } = payload

    // Generate a new token
    const newToken = await auth.sign(userData, { expiresIn: '1h' })

    // Set the new token as a cookie
    setCookie(c, 'cf-jwt-token', newToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: 60 * 60, // 1 hour
      path: '/'
    })

    return c.json({ token: newToken, success: true })
  } catch (err) {
    return c.json({ message: 'Invalid token', success: false }, 401)
  }
})

// Logout endpoint
app.post('/logout', (c) => {
  // Clear the cookie
  setCookie(c, 'cf-jwt-token', '', {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    maxAge: 0,
    path: '/'
  })

  return c.json({ message: 'Logged out successfully', success: true })
})

export default app