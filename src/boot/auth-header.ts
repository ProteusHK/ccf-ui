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

/**
 * Consider any URL whose path starts with "/api/" as an API call,
 * regardless of origin (supports external API_URL).
 */
function isApi(url: string): boolean {
  try {
    const u = new URL(url, window.location.origin);
    return u.pathname.startsWith('/api/');
  } catch {
    return false;
  }
}

/* -------------------- fetch patch -------------------- */
const _fetch = window.fetch.bind(window);

window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
  // Normalize URL for detection
  const url =
    typeof input === 'string'
      ? input
      : input instanceof URL
      ? input.toString()
      : (input as Request).url;

  // If not an API call, pass through
  if (!isApi(url)) {
    return _fetch(input as any, init as any);
  }

  // Merge headers: start with headers on the Request (if present),
  // then overlay init.headers (caller intent wins), then add Authorization if absent.
  const merged = new Headers(
    input instanceof Request ? (input as Request).headers : undefined
  );
  if (init?.headers) {
    new Headers(init.headers).forEach((v, k) => {
      merged.set(k, v);
    });
  }
  if (!merged.has('Authorization')) {
    const t = getToken();
    if (t) merged.set('Authorization', `Bearer ${t}`);
  }

  // Rebuild when input is a Request so our merged headers are guaranteed to be applied.
  let res: Response;
  if (input instanceof Request) {
    const req = new Request(input, { ...init, headers: merged });
    res = await _fetch(req);
  } else {
    res = await _fetch(input as any, { ...init, headers: merged });
  }

  // Capture token on successful login
  try {
    const p = new URL(url, location.origin).pathname;
    if (/\/api\/auth\/login$/.test(p) && res.ok) {
      let body: any = null;
      try {
        body = await res.clone().json();
      } catch {
        body = null;
      }
      const token = body?.data?.auth_token;
      if (typeof token === 'string' && token.length > 0) setToken(token);
    }
  } catch {
    /* noop */
  }

  return res;
};

/* -------------------- XHR (axios) patch -------------------- */
const XO = XMLHttpRequest.prototype.open;
const XS = XMLHttpRequest.prototype.send;

(XMLHttpRequest.prototype as any)._ccf_open = XO;
(XMLHttpRequest.prototype as any)._ccf_send = XS;

(XMLHttpRequest.prototype as any).open = function (
  this: XMLHttpRequest,
  method: string,
  url: string,
  async: boolean = true,
  username?: string | null,
  password?: string | null
) {
  (this as any).__ccf_is_api = isApi(url);
  return XO.call(this, method, url, async, username, password);
};

(XMLHttpRequest.prototype as any).send = function (
  this: XMLHttpRequest,
  body?: Document | XMLHttpRequestBodyInit | null
) {
  // Attach Authorization to outgoing XHRs
  if ((this as any).__ccf_is_api) {
    try {
      const t = getToken();
      if (t) this.setRequestHeader('Authorization', `Bearer ${t}`);
    } catch {
      /* noop */
    }
  }

  // Persist JWT when login is performed via XHR (axios)
  this.addEventListener(
    'load',
    function (this: XMLHttpRequest) {
      try {
        if (!(this as any).__ccf_is_api) return;

        const url = new URL(this.responseURL);
        const path = url.pathname;

        // Capture token on successful login
        if (/\/api\/auth\/login$/.test(path) && this.status >= 200 && this.status < 300) {
          let json: any = null;
          try {
            // axios often sets responseType='json'; prefer parsed object if present
            if (this.response && typeof this.response === 'object') {
              json = this.response;
            } else {
              const txt = this.responseText || '';
              json = txt ? JSON.parse(txt) : null;
            }
          } catch {
            json = null;
          }
          const token = json?.data?.auth_token;
          if (typeof token === 'string' && token.length > 0) setToken(token);
        }

        // Optional hygiene: clear token on logout or unauthorized
        if (/\/api\/auth\/logout$/.test(path) && this.status >= 200 && this.status < 300) {
          clearToken();
        }
        if (this.status === 401) {
          clearToken();
        }
      } catch {
        /* noop */
      }
    },
    { once: true }
  );

  return XS.call(this, body);
};
