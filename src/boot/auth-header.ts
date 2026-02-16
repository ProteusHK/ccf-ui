/* Boot patch: persist JWT from /api/auth/login and attach Authorization on all /api/* calls.
   Works for both native fetch and axios (XHR) without touching the build pipeline. */

const TOKEN_KEY = 'ccf_auth_token';

function getToken(): string {
  try {
    return localStorage.getItem(TOKEN_KEY) || '';
  } catch {
    return '';
  }
}

function setToken(t?: string) {
  try {
    if (t) localStorage.setItem(TOKEN_KEY, t);
  } catch {
    /* noop */
  }
}

function clearToken() {
  try {
    localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* noop */
  }
}

function isApi(url: string): boolean {
  try {
    const u = new URL(url, window.location.origin);
    return u.pathname.startsWith('/api/');
  } catch {
    return false;
  }
}

// Patch fetch
const _fetch = window.fetch.bind(window);
window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = typeof input === 'string' ? input : (input as Request).url;
  let cfg = init;

  if (isApi(url)) {
    cfg = { ...init, headers: new Headers((init && init.headers) || {}) };
    const h = cfg.headers as Headers;
    if (!h.has('Authorization')) {
      const t = getToken();
      if (t) h.set('Authorization', `Bearer ${t}`);
    }
  }

  const res = await _fetch(input, cfg);

  // Capture token on successful login
  try {
    if (isApi(url) && /\/api\/auth\/login$/.test(new URL(url, location.origin).pathname) && res.ok) {
      const clone = res.clone();
      const body = await clone.json().catch(() => null);
      const token = body && body.data && body.data.auth_token;
      if (typeof token === 'string' && token.length > 0) setToken(token);
    }
  } catch {
    /* noop */
  }

  return res;
};

// Patch XHR (axios defaults to XHR in browsers)
const XO = XMLHttpRequest.prototype.open;
const XS = XMLHttpRequest.prototype.send;

(XMLHttpRequest.prototype as any)._ccf_open = XO;
(XMLHttpRequest.prototype as any)._ccf_send = XS;

(XMLHttpRequest.prototype as any).open = function (method: string, url: string, ...rest: any[]) {
  (this as any).__ccf_is_api = isApi(url);
  return XO.apply(this, [method, url, ...rest]);
};

(XMLHttpRequest.prototype as any).send = function (body?: Document | BodyInit | null) {
  if ((this as any).__ccf_is_api) {
    try {
      const t = getToken();
      if (t) this.setRequestHeader('Authorization', `Bearer ${t}`);
    } catch {
      /* noop */
    }
  }
  return XS.apply(this, [body]);
};

// Optional helper exposed for debugging
(window as any).__ccfAuth = {
  getToken,
  setToken,
  clearToken,
};
