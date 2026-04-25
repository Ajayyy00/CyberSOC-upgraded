/* ============================================================
   CyberSOC Dashboard — WebSocket API Client

   Maintains a persistent WebSocket connection to /ws/{session_id}.
   Each browser tab gets its own session_id (UUID in sessionStorage),
   giving every tab an isolated CyberSOCEnvironment on the server.

   Public surface (unchanged from the old fetch-based API):
     API.reset(taskId)  → Promise<observation>
     API.step(action)   → Promise<observation>
     API.getState()     → { active, session_id }
     API.checkConnection() → Promise<boolean>

   Internal protocol (client → server):
     { type: "reset", task_id: "hard" }
     { type: "step",  ...action fields }
     { type: "ping" }

   Internal protocol (server → client):
     { type: "reset_ok", observation: {...}, reward, done }
     { type: "step_ok",  observation: {...}, reward, done }
     { type: "error",    message: "..." }
     { type: "pong" }
   ============================================================ */

const API = (() => {

  // ── Session ID ─────────────────────────────────────────────────────────────
  // UUIDs are stored in sessionStorage so each tab has its own session but
  // the same tab survives a page refresh.
  function _uuid() {
    if (typeof crypto !== 'undefined' && crypto.randomUUID) {
      return crypto.randomUUID();
    }
    // Fallback for older browsers
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
  }

  const _sessionId = (() => {
    try {
      let id = sessionStorage.getItem('soc_session_id');
      if (!id) { id = _uuid(); sessionStorage.setItem('soc_session_id', id); }
      return id;
    } catch {
      return _uuid(); // sessionStorage blocked (e.g. private mode with strict settings)
    }
  })();

  // ── External backend override (set by dashboard/js/config.js in Demo mode) ─
  // config.js sets window.CYBERSOC_BACKEND_URL to the trainer Space URL.
  // Empty string → auto-detect from page origin (default for full-stack mode).
  const _backendOverride = (
    typeof window !== 'undefined' &&
    typeof window.CYBERSOC_BACKEND_URL === 'string' &&
    window.CYBERSOC_BACKEND_URL.trim()
  ) ? window.CYBERSOC_BACKEND_URL.trim().replace(/\/$/, '') : '';

  // ── WebSocket URL ──────────────────────────────────────────────────────────
  function _wsUrl() {
    if (_backendOverride) {
      const wsProto = _backendOverride.startsWith('https') ? 'wss:' : 'ws:';
      const host    = _backendOverride.replace(/^https?:\/\//, '');
      return `${wsProto}//${host}/ws/${_sessionId}`;
    }
    if (typeof window === 'undefined') {
      return `ws://localhost:8000/ws/${_sessionId}`;
    }
    const { protocol, hostname, port } = window.location;
    if (protocol === 'file:') return `ws://localhost:8000/ws/${_sessionId}`;
    const wsProto = protocol === 'https:' ? 'wss:' : 'ws:';
    const host    = port ? `${hostname}:${port}` : hostname;
    return `${wsProto}//${host}/ws/${_sessionId}`;
  }

  // HTTP base URL — used only by checkConnection() which pings /health over HTTP
  function _httpBase() {
    if (_backendOverride) return _backendOverride;
    if (typeof window === 'undefined') return 'http://localhost:8000';
    const { protocol, hostname, port } = window.location;
    if (protocol === 'file:') return 'http://localhost:8000';
    return port ? `${protocol}//${hostname}:${port}` : `${protocol}//${hostname}`;
  }

  // ── StateStore reference (injected by app.js via setStore) ──────────────────
  let _store = null;

  // ── WebSocket state ────────────────────────────────────────────────────────
  let _ws               = null;
  let _connected        = false;
  let _reconnectAttempts = 0;
  let _reconnectTimer   = null;
  let _pingInterval     = null;

  // At most one request is in-flight at a time; the dashboard actions are sequential.
  // _pending holds the callbacks and a timeout handle for the current in-flight request.
  let _pending = null;  // { resolve, reject, timeoutId } | null

  const MAX_RECONNECT  = 8;
  const BACKOFF_MS     = [500, 1000, 2000, 4000, 8000, 16000, 30000, 60000];
  const REQUEST_TIMEOUT_MS = 30_000;
  const PING_INTERVAL_MS   = 25_000; // keep connection alive through proxies/HF Spaces

  // ── Pending promise helpers ────────────────────────────────────────────────
  function _resolvePending(data) {
    if (!_pending) return;
    clearTimeout(_pending.timeoutId);
    _pending.resolve(data);
    _pending = null;
  }

  function _rejectPending(reason) {
    if (!_pending) return;
    clearTimeout(_pending.timeoutId);
    _pending.reject(new Error(reason));
    _pending = null;
  }

  // ── Ping keepalive ─────────────────────────────────────────────────────────
  function _startPing() {
    _stopPing();
    _pingInterval = setInterval(() => {
      if (_ws && _ws.readyState === WebSocket.OPEN && !_pending) {
        _ws.send(JSON.stringify({ type: 'ping' }));
      }
    }, PING_INTERVAL_MS);
  }

  function _stopPing() {
    if (_pingInterval !== null) { clearInterval(_pingInterval); _pingInterval = null; }
  }

  // ── Connection ─────────────────────────────────────────────────────────────
  function _connect() {
    if (_ws && (_ws.readyState === WebSocket.CONNECTING ||
                _ws.readyState === WebSocket.OPEN)) return;

    const url = _wsUrl();
    _ws = new WebSocket(url);

    _ws.onopen = () => {
      _connected        = true;
      _reconnectAttempts = 0;
      _reconnectTimer   = null;
      console.log('[WS] connected →', url);
      _startPing();
    };

    _ws.onmessage = (event) => {
      let msg;
      try { msg = JSON.parse(event.data); } catch { return; }

      switch (msg.type) {
        case 'reset_ok':
        case 'step_ok':
          _resolvePending(msg);
          break;
        case 'error':
          _rejectPending(msg.message || 'Server error');
          break;
        case 'pong':
          break; // keepalive reply — nothing to do
        default:
          console.warn('[WS] unknown message type:', msg.type);
      }
    };

    _ws.onclose = (ev) => {
      _connected = false;
      _stopPing();
      _rejectPending('WebSocket disconnected');
      console.warn(`[WS] closed (code ${ev.code}) — scheduling reconnect`);
      _scheduleReconnect();
    };

    _ws.onerror = () => {
      // onclose always fires after onerror; handle everything there
      console.warn('[WS] connection error');
    };
  }

  function _scheduleReconnect() {
    if (_reconnectTimer !== null) return; // already pending
    if (_reconnectAttempts >= MAX_RECONNECT) {
      console.error('[WS] max reconnect attempts reached — giving up');
      return;
    }
    const delay = BACKOFF_MS[Math.min(_reconnectAttempts, BACKOFF_MS.length - 1)];
    _reconnectAttempts++;
    console.log(`[WS] reconnect attempt ${_reconnectAttempts}/${MAX_RECONNECT} in ${delay}ms`);
    _reconnectTimer = setTimeout(() => { _reconnectTimer = null; _connect(); }, delay);
  }

  // ── Send helper ────────────────────────────────────────────────────────────
  // Returns a Promise that resolves with the server's response message,
  // or rejects on error / timeout / disconnect.
  function _send(msg) {
    return new Promise((resolve, reject) => {
      if (_pending) {
        reject(new Error('Another request is already in-flight — try again'));
        return;
      }

      const timeoutId = setTimeout(() => {
        _pending = null;
        reject(new Error(`Request timed out after ${REQUEST_TIMEOUT_MS / 1000}s`));
      }, REQUEST_TIMEOUT_MS);

      _pending = { resolve, reject, timeoutId };

      const payload = JSON.stringify(msg);

      if (_ws && _ws.readyState === WebSocket.OPEN) {
        _ws.send(payload);
        return;
      }

      // Not open yet — ensure we're connecting, then poll until open or failed
      if (!_ws || _ws.readyState === WebSocket.CLOSED ||
                  _ws.readyState === WebSocket.CLOSING) {
        _connect();
      }

      const poll = setInterval(() => {
        if (!_pending) { clearInterval(poll); return; } // timed out or rejected already
        if (_ws && _ws.readyState === WebSocket.OPEN) {
          clearInterval(poll);
          _ws.send(payload);
        } else if (!_ws || _ws.readyState === WebSocket.CLOSED) {
          clearInterval(poll);
          _rejectPending('WebSocket closed before message could be sent');
        }
      }, 100);
    });
  }

  // ── Response parser (same shape as the old fetch-based version) ────────────
  function _parseResponse(msg) {
    if (!msg) return null;
    const obs = msg.observation || msg;
    return {
      episode_id:            obs.episode_id            || '',
      alert_queue:           obs.alert_queue           || [],
      network_topology:      obs.network_topology      || { total_hosts: 0, subnets: {}, compromised_count: 0, isolated_count: 0, online_count: 0 },
      host_forensics:        obs.host_forensics        || null,
      timeline:              obs.timeline              || [],
      business_impact_score: obs.business_impact_score ?? 0,
      step_count:            obs.step_count            ?? 0,
      active_threats:        obs.active_threats        || [],
      max_steps:             obs.max_steps             || 30,
      task_id:               obs.task_id               || 'hard',
      total_reward:          obs.total_reward          ?? 0,
      final_score:           obs.final_score           ?? null,
      grade_breakdown:       obs.grade_breakdown       || null,
      correlation_results:   obs.correlation_results   || null,
      ioc_enrichment:        obs.ioc_enrichment        || null,
      vulnerability_results: obs.vulnerability_results || null,
      playbook_result:       obs.playbook_result       || null,
      threat_graph_summary:  obs.threat_graph_summary  || null,
      available_playbooks:   obs.available_playbooks   || [],
      done:                  msg.done   ?? obs.done   ?? false,
      reward:                msg.reward ?? obs.reward ?? 0,
      active_turn:           obs.active_turn || null,
    };
  }

  // Eagerly open the WebSocket so it's ready before the user clicks Start
  _connect();

  // ── Public API ─────────────────────────────────────────────────────────────
  return {

    // Inject the StateStore so every parsed response is pushed into it.
    // Called once from CyberSOCDashboard.init() before any episode starts.
    setStore(store) {
      _store = store;
    },

    // Send a reset message, push parsed observation into the store, return it.
    async reset(taskId = 'hard') {
      const msg    = await _send({ type: 'reset', task_id: taskId });
      const parsed = _parseResponse(msg);
      _store?.applyObservation(parsed, null);
      return parsed;
    },

    // Send a step message, push parsed observation into the store, return it.
    async step(action) {
      const msg    = await _send({ type: 'step', ...action });
      const parsed = _parseResponse(msg);
      _store?.applyObservation(parsed, action);
      return parsed;
    },

    // Local state — no server round-trip needed
    getState() {
      return { active: _connected, session_id: _sessionId };
    },

    // HTTP /health ping — used by the connection overlay on page load.
    // Deliberately stays on HTTP so it never races with the WS handshake.
    async checkConnection() {
      try {
        const r = await fetch(`${_httpBase()}/health`, {
          signal: AbortSignal.timeout(3000),
        });
        return r.ok;
      } catch {
        return false;
      }
    },
  };

})();
