/* ============================================================
   CyberSOC Dashboard — API Client
   Talks to the FastAPI CyberSOCEnv server at localhost:8000
   ============================================================ */

const API = {
  // When served from the dashboard_server.py at /dashboard/ use same-origin relative URLs.
  // When opened as file:// or from any other origin, fall back to absolute localhost:8000.
  baseUrl: (() => {
    if (typeof window === 'undefined') return 'http://localhost:8000';
    const { protocol, hostname, port } = window.location;
    if (protocol === 'file:') return 'http://localhost:8000';
    if (hostname === 'localhost' && (port === '8000' || !port)) return '';
    return 'http://localhost:8000';
  })(),
  sessionId: null,

  // Parse the server response — handles both wrapped {observation: {...}}
  // and flat observation formats
  _parseResponse(data) {
    if (!data) return null;
    // Prefer wrapped format (per client.py's _parse_result)
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

  async reset(taskId = 'hard') {
    const url = `${this.baseUrl}/reset`;
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
    // Store session ID if the server provides one
    const sessionHeader = response.headers.get('X-Session-Id') || response.headers.get('x-session-id');
    if (sessionHeader) this.sessionId = sessionHeader;
    if (data.session_id) this.sessionId = data.session_id;
    return this._parseResponse(data);
  },

  async step(action) {
    const url = `${this.baseUrl}/step`;
    const headers = { 'Content-Type': 'application/json' };
    if (this.sessionId) headers['X-Session-Id'] = this.sessionId;

    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(action),
    });
    if (!response.ok) {
      // Try alternate format: {action: {...}}
      const altResponse = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify({ action }),
      });
      if (!altResponse.ok) {
        const errText = await altResponse.text();
        throw new Error(`Step failed: ${altResponse.status} — ${errText.substring(0, 200)}`);
      }
      const data = await altResponse.json();
      return this._parseResponse(data);
    }
    const data = await response.json();
    return this._parseResponse(data);
  },

  async getState() {
    const url = `${this.baseUrl}/state`;
    const headers = {};
    if (this.sessionId) headers['X-Session-Id'] = this.sessionId;
    const response = await fetch(url, { headers });
    if (!response.ok) return null;
    return response.json();
  },

  async checkConnection() {
    try {
      // Try /state first, fall back to root
      const r = await fetch(`${this.baseUrl}/state`, {
        signal: AbortSignal.timeout(3000),
      });
      return r.ok || r.status === 404; // 404 = server alive, no state yet
    } catch {
      try {
        const r2 = await fetch(this.baseUrl, { signal: AbortSignal.timeout(3000) });
        return true;
      } catch {
        return false;
      }
    }
  },
};
