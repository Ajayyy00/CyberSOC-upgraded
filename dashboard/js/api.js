/* ============================================================
   CyberSOC Dashboard — API Client

   Uses /demo/reset and /demo/step which are STATEFUL endpoints
   provided by dashboard_server.py.  These keep one live
   CyberSOCEnvironment instance in memory between calls, unlike
   OpenEnv's built-in /reset and /step which are stateless
   (they create a fresh env per request and destroy it afterwards).
   ============================================================ */

const API = {
  // Detect the correct base URL for the API server.
  // dashboard_server.py serves both the static dashboard AND the
  // /demo/* REST endpoints from the same origin, so we use relative
  // URLs in production and absolute localhost URLs for local dev
  // (served by a simple HTTP server on a different port).
  baseUrl: (() => {
    if (typeof window === 'undefined') return 'http://localhost:8000';
    const { protocol, hostname, port } = window.location;
    // Opened as a local file
    if (protocol === 'file:') return 'http://localhost:8000';
    // Served by dashboard_server.py on port 8000 (same origin)
    if (hostname === 'localhost' && (port === '8000' || !port)) return '';
    // HuggingFace Spaces (*.hf.space) — same origin as dashboard_server
    if (hostname.endsWith('.hf.space')) return '';
    // Local dev server on any other port (e.g. 8080) — API is at 8000
    if (hostname === 'localhost') return 'http://localhost:8000';
    // Any other deployment — assume same origin
    return '';
  })(),

  // Parse the server response — handles both wrapped {observation: {...}}
  // and flat observation formats
  _parseResponse(data) {
    if (!data) return null;
    // Prefer wrapped format
    const obs = data.observation || data;
    return {
      // Core observation fields
      episode_id: obs.episode_id || '',
      alert_queue: obs.alert_queue || [],
      network_topology: obs.network_topology || { total_hosts: 0, subnets: {}, compromised_count: 0, isolated_count: 0, online_count: 0 },
      host_forensics: obs.host_forensics || null,
      timeline: obs.timeline || [],
      business_impact_score: obs.business_impact_score ?? 0,
      step_count: obs.step_count ?? 0,
      active_threats: obs.active_threats || [],
      max_steps: obs.max_steps || 30,
      task_id: obs.task_id || 'hard',
      total_reward: obs.total_reward ?? 0,
      final_score: obs.final_score ?? null,
      grade_breakdown: obs.grade_breakdown || null,
      correlation_results: obs.correlation_results || null,
      ioc_enrichment: obs.ioc_enrichment || null,
      vulnerability_results: obs.vulnerability_results || null,
      playbook_result: obs.playbook_result || null,
      threat_graph_summary: obs.threat_graph_summary || null,
      available_playbooks: obs.available_playbooks || [],
      // Done/reward can be at top level or in obs
      done: data.done ?? obs.done ?? false,
      reward: data.reward ?? obs.reward ?? 0,
    };
  },

  // POST /demo/reset  — starts a new stateful episode on the server
  async reset(taskId = 'hard') {
    const url = `${this.baseUrl}/demo/reset`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ task_id: taskId }),
    });
    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`Reset failed: ${response.status} — ${errText.substring(0, 200)}`);
    }
    const data = await response.json();
    return this._parseResponse(data);
  },

  // POST /demo/step  — sends action to the SAME env instance created by reset
  // Body: the action fields directly (task_id, type, hostname, etc.)
  // dashboard_server's /demo/step expects the action fields at the top level.
  async step(action) {
    const url = `${this.baseUrl}/demo/step`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(action),
    });
    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`Step failed: ${response.status} — ${errText.substring(0, 200)}`);
    }
    const data = await response.json();
    return this._parseResponse(data);
  },

  async getState() {
    const url = `${this.baseUrl}/demo/state`;
    const response = await fetch(url);
    if (!response.ok) return null;
    return response.json();
  },

  async checkConnection() {
    // Use /health endpoint — never /state — to avoid fetching and
    // accidentally rendering stale episode data from a previous session.
    try {
      const r = await fetch(`${this.baseUrl}/health`, {
        signal: AbortSignal.timeout(3000),
      });
      if (r.ok) return true;
    } catch { /* fall through */ }
    // Fallback: ping root
    try {
      const r2 = await fetch(`${this.baseUrl}/`, {
        signal: AbortSignal.timeout(3000),
      });
      return r2.ok;
    } catch {
      return false;
    }
  },
};
