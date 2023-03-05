import moment from 'moment';

const UPSTREAM_URL = 'https://api.openai.com/v1/chat/completions';
const ORG_ID_REGEX = /\borg-[a-zA-Z0-9]{24}\b/g; // used to obfuscate any org IDs in the response text
const MAX_REQUESTS = 1024; // maximum number of requests per IP address per hour

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, BREW',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

const STREAM_HEADERS = {
  'Content-Type': 'text/event-stream',
  'Connection': 'keep-alive',
};

const ALLOWED_DOMAINS = ['*.llego.dev'];

const API_KEYS = JSON.parse(env.API_KEYS);

// Define a function that hashes a string with SHA-256 and a salt value
const sha256 = async (message, salt) => {
  const data = new TextEncoder().encode(`${message}${salt}`);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
};

// Define a function to select an API key randomly from a list
const randomChoice = (arr) => {
  if (arr.length === 0) {
    throw new Error('Cannot get a random choice from an empty array');
  }
  const randomIndex = Math.floor(Math.random() * arr.length);
  return arr[randomIndex];
};

// Define a function that hashes user IP address, UTC year, month, day, day of the week, hour, and the secret key
//
// To implement IP-based rate limiting, we have to store users' IP addresses in a certain way. However, we want to protect
// users' privacy as much as possible. To achieve this, we use SHA-256 to calculate a digest value of the user's IP address
// along with the UTC year, month, day, day of the week, hour, and the secret key. The resulting digest not only depends on
// the user's IP address but is also unique to each hour, making the user's IP address hard to be determined. Moreover, the
// one-way nature of the SHA-256 algorithm implies that even if the digest value is compromised, it is almost impossible to
// reverse it to obtain the original IP address, ensuring the privacy and security of the user's identity.
const hashIp = async (ip, utcNow, secret_key) => {
  const salt = crypto.getRandomValues(new Uint8Array(16)).join('');
  const message = `${utcNow.format('ddd=DD.MM-HH+YYYY')}-${ip}:${secret_key}`;
  try {
    const hash = await sha256(message, salt);
    return { hash, salt };
  } catch (error) {
    console.error(`Error hashing message: ${message}`, error);
    throw new Error('Error hashing IP address');
  }
};

const handleRequest = async (request, env) => {
  try {
    // Code for handling request
    let requestBody;
    try {
      requestBody = await request.json();
    } catch (error) {
      return new Response('Malformed JSON', { status: 422, headers: CORS_HEADERS });
    }

    const stream = requestBody.stream === true;
    if (requestBody.stream != null && !stream) {
      return new Response('The `stream` parameter must be a boolean value', { status: 400, headers: CORS_HEADERS });
    }

    // Check if the request is coming from an allowed domain
    const domain = new URL(request.referrer).host;
    if (!ALLOWED_DOMAINS.some((allowed) => domain.endsWith(allowed.substring(1)))) {
      return new Response('Forbidden', { status: 403, headers: CORS_HEADERS });
    }

    // Enforce the rate limit based on hashed client IP address
    const utcNow = moment.utc();
    const clientIp = request.headers.get('CF-Connecting-IP');
    const { hash: clientIpHash, salt: clientIpSalt } = await hashIp(clientIp, utcNow, env.SECRET_KEY);
    const rateLimitKey = `rate_limit_${clientIpHash}`;
    const rateLimitData = (await env.kv.get(rateLimitKey, { type: 'json' })) || {};
    const { rateLimitCount = 0, rateLimitExpiration = utcNow.startOf('hour').add(1, 'hour').unix() } = rateLimitData;
    if (rateLimitCount > MAX_REQUESTS) {
      return new Response('Too many requests please try again later', { status: 429, headers: CORS_HEADERS });
    }

    // Forward a POST request to the upstream URL and return the response
    const api_key = randomChoice(API_KEYS);
    const upstreamResponse = await fetch(UPSTREAM_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${api_key}`,
        'User-Agent': 'curl/7.64.1',
      },
      body: JSON.stringify(requestBody),
    });

    if (!upstreamResponse.ok) {
      const { status } = upstreamResponse;
      const text = await upstreamResponse.text();
      const textObfuscated = text.replace(ORG_ID_REGEX, 'org-************************');
      return new Response(`OpenAI API responded with:\n\n${textObfuscated}`, { status, header: CORS_HEADERS });
    }

    // Update the rate limit information
    const rateLimitDataNew = {
      rateLimitCount: rateLimitCount + 1,
      rateLimitExpiration,
    };
    await env.kv.put(rateLimitKey, JSON.stringify(rateLimitDataNew), { expiration: rateLimitExpiration });

    return new Response(upstreamResponse.body, {
      headers: {
        ...CORS_HEADERS,
        ...(stream && STREAM_HEADERS),
        'Cache-Control': 'no-cache',
      },
    });
  } catch (error) {
    console.error(error);

    let message = 'Internal Server Error';
    let status = 500;

    if (error instanceof Response) {
      // If error is coming from upstream API, reflect it back to the client
      message = await error.text();
      status = error.status;

      console.error(`Upstream API responded with:\n\n${message}`);
    } else if (error instanceof TypeError) {
      // If error is caused by a programming error like incorrect arguments, etc.
      message = error.message;
      status = 400;
    }

    return new Response(message, { status, headers: CORS_HEADERS });
  }
};

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    if (pathname !== '/v1/') {
      return new Response('Not Found', { status: 404, headers: CORS_HEADERS });
    }
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          ...CORS_HEADERS,
          'Access-Control-Max-Age': '1728000',
        },
      });
    }

    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405, headers: CORS_HEADERS });
    }

    const contentType = request.headers.get('Content-Type');
    if (!contentType || contentType !== 'application/json') {
      return new Response("Unsupported media type. Use 'application/json' content type", { status: 415, headers: CORS_HEADERS });
    }

    return await handleRequest(request, env);
  },
};
