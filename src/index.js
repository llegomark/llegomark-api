import moment from 'moment';

const UPSTREAM_URL = 'https://api.openai.com/v1/chat/completions';
const ORG_ID_REGEX = /\borg-[a-zA-Z0-9]{24}\b/g;
const MAX_REQUESTS = 20;

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': 'https://chat.llego.dev',
  'Access-Control-Allow-Methods': 'GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, BREW',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

const STREAM_HEADERS = {
  'Content-Type': 'text/event-stream',
  'Connection': 'keep-alive',
};

const sha256 = async (message) => {
  const data = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
};

const randomChoice = (arr) => arr[Math.floor(Math.random() * arr.length)];

const obfuscateOpenAIResponse = (text) => text.replace(ORG_ID_REGEX, 'org-************************').replace(' Please add a payment method to your account to increase your rate limit. Visit https://platform.openai.com/account/billing to add a payment method.', '');

const hashIp = (ip, utcNow, secret_key) => sha256(`${utcNow.format('ddd=DD.MM-HH+YYYY')}-${ip}:${secret_key}`);

const handleRateLimit = async (request, env, utcNow, clientIpHash) => {
  const rateLimitKey = `rate_limit_${clientIpHash}`;
  const rateLimitExpiration = utcNow.startOf('hour').add(1, 'hour').unix();
  const { rateLimitCount = 0 } = (await env.kv.get(rateLimitKey, { type: 'json' })) || {};

  if (rateLimitCount > MAX_REQUESTS) {
    return new Response('You have exceeded the maximum limit of 20 requests. Please try again in one hour.', { status: 429, headers: CORS_HEADERS });
  }

  await env.kv.put(rateLimitKey, JSON.stringify({ rateLimitCount: rateLimitCount + 1 }), { expiration: rateLimitExpiration });
};

const handleApiKeySelection = (env) => {
  return randomChoice(JSON.parse(env.API_KEYS));
};

const handleUpstreamRequest = async (requestBody, api_key) => {
  const upstreamResponse = await fetch(UPSTREAM_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${api_key}`,
      'User-Agent': 'curl/7.88.1',
    },
    body: JSON.stringify(requestBody),
  });

  if (!upstreamResponse.ok) {
    const { status } = upstreamResponse;
    const text = await upstreamResponse.text();
    const textObfuscated = obfuscateOpenAIResponse(text);
    return new Response(`Mark Anthony Llego API responded with:\n\n${textObfuscated}`, { status, headers: CORS_HEADERS });
  }

  return upstreamResponse;
};

const handleRequest = async (request, env) => {
  let requestBody;

  try {
    requestBody = await request.json();
  } catch (error) {
    return new Response('Malformed JSON', { status: 422, headers: CORS_HEADERS });
  }

  const { stream } = requestBody;

  if (stream != null && stream !== true && stream !== false) {
    return new Response('The `stream` parameter must be a boolean value.', { status: 400, headers: CORS_HEADERS });
  }

  try {
    const utcNow = moment.utc();
    const clientIp = request.headers.get('CF-Connecting-IP');
    const clientIpHash = await hashIp(clientIp, utcNow, env.SECRET_KEY);

    await handleRateLimit(request, env, utcNow, clientIpHash);

    const api_key = handleApiKeySelection(env);

    const upstreamResponse = await handleUpstreamRequest(requestBody, api_key);

    return new Response(upstreamResponse.body, {
      headers: {
        ...CORS_HEADERS,
        ...(stream && STREAM_HEADERS),
        'Cache-Control': 'no-cache',
      },
    });
  } catch (error) {
    return new Response(error.message, { status: 500, headers: CORS_HEADERS });
  }
};

const handlePreflightRequest = () => {
  return new Response(null, {
    headers: {
      ...CORS_HEADERS,
      'Access-Control-Max-Age': '1728000',
    },
  });
};

const handleInvalidContentType = () => {
  return new Response("Unsupported media type. Use 'application/json' content type.", { status: 415, headers: CORS_HEADERS });
};

const handleInvalidMethod = () => {
  return new Response('Method not allowed.', { status: 405, headers: CORS_HEADERS });
};

const handleInvalidResource = () => {
  return new Response('You are not allowed to access this resource.', { status: 403, headers: CORS_HEADERS });
};

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);

    if (pathname !== '/v1/') {
      return handleInvalidResource();
    }

    if (request.method === 'OPTIONS') {
      return handlePreflightRequest();
    }

    if (request.method !== 'POST') {
      return handleInvalidMethod();
    }

    const contentType = request.headers.get('Content-Type');

    if (!contentType || contentType !== 'application/json') {
      return handleInvalidContentType();
    }

    return handleRequest(request, env);
  },
};
