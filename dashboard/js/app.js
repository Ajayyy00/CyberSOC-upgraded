/* ============================================================
   CyberSOC Dashboard — Main Application Controller
   ============================================================ */

class CyberSOCDashboard {
  constructor() {
    this.api = API;
    this.threatGraph = new ClientThreatGraph();
    this.graphViz = new ThreatGraphViz('threat-graph-container');
    this.radarChart = new RadarChart('radar-chart');
    this.rewardTimeline = new RewardTimeline('reward-timeline');

    this.currentObs = null;
    this.demoActions = [];
    this.currentStepIndex = 0;
    this.autoPlayTimer = null;
    this.episodeStartTime = null;
    this.timerInterval = null;
    this.isPaused = false;
    this.episodeRunning = false;
    this.prevAlertIds = new Set();
    this.currentAction = null;

    // Live score estimates (updated heuristically during episode)
    this.liveScores = {
      threat_containment: 0, ioc_blocking: 0, forensic_investigation: 0,
      siem_correlation: 0, threat_intel_usage: 0, vuln_root_cause: 0,
      business_impact: 1.0, step_efficiency: 0.5, plan_coverage: 0, plan_evidence_quality: 0,
    };
    this.containmentState = {
      processed_killed: 0, processes_total: 0,
      iocs_blocked: 0, iocs_total: 0,
      hosts_investigated: 0, hosts_total: 0,
      playbooks_triggered: 0, playbooks_total: 2,
    };
  }

  async init() {
    AnimationUtils.init();
    this.graphViz.init();
    this.radarChart.init();
    this.rewardTimeline.init();
    this._bindButtons();
    this._showConnectionOverlay('Connecting to CyberSOC Server...');
    await this._waitForServer();
  }

  async _waitForServer() {
    let attempts = 0;
    const maxAttempts = 30;
    const check = async () => {
      attempts++;
      const ok = await this.api.checkConnection();
      if (ok) {
        this._hideConnectionOverlay();
        AnimationUtils.showNotification('✅ Connected to CyberSOC Server', 'green', 2000);
        document.getElementById('btn-start').disabled = false;
      } else if (attempts < maxAttempts) {
        this._showConnectionOverlay(`Connecting to CyberSOC Server... (${attempts}/${maxAttempts})`);
        setTimeout(check, 2000);
      } else {
        this._showConnectionOverlay('⚠️ Server not available. Start with: uvicorn server.app:app --port 8000');
        document.getElementById('btn-start').disabled = false; // Allow manual start attempt
      }
    };
    await check();
  }

  _bindButtons() {
    document.getElementById('btn-start').addEventListener('click', () => this._onStartClick());
    document.getElementById('btn-pause').addEventListener('click', () => this._onPauseClick());
    document.getElementById('btn-next').addEventListener('click', () => this._onNextClick());
    document.getElementById('btn-reset').addEventListener('click', () => this._onResetClick());
  }

  async _onStartClick() {
    const taskId = document.getElementById('task-select').value;
    await this.startEpisode(taskId);
  }

  _onPauseClick() {
    this.isPaused = !this.isPaused;
    const btn = document.getElementById('btn-pause');
    if (this.isPaused) {
      btn.textContent = '▶ Resume';
      if (this.autoPlayTimer) { clearTimeout(this.autoPlayTimer); this.autoPlayTimer = null; }
    } else {
      btn.textContent = '⏸ Pause';
      this._scheduleNextStep();
    }
  }

  _onNextClick() {
    if (this.autoPlayTimer) { clearTimeout(this.autoPlayTimer); this.autoPlayTimer = null; }
    this.isPaused = true;
    document.getElementById('btn-pause').textContent = '▶ Resume';
    this._executeNextStep();
  }

  async _onResetClick() {
    this.isPaused = false;
    this.episodeRunning = false;
    if (this.autoPlayTimer) { clearTimeout(this.autoPlayTimer); this.autoPlayTimer = null; }
    if (this.timerInterval) { clearInterval(this.timerInterval); this.timerInterval = null; }

    // Reset UI
    document.getElementById('btn-start').classList.remove('hidden');
    document.getElementById('btn-pause').classList.add('hidden');
    document.getElementById('btn-next').classList.add('hidden');
    document.getElementById('btn-reset').classList.add('hidden');
    document.getElementById('task-select').disabled = false;

    this._resetUI();
  }

  // ============================================================
  // Episode Management
  // ============================================================

  async startEpisode(taskId) {
    document.getElementById('btn-start').classList.add('hidden');
    document.getElementById('task-select').disabled = true;
    document.getElementById('btn-pause').classList.remove('hidden');
    document.getElementById('btn-next').classList.remove('hidden');
    document.getElementById('btn-reset').classList.remove('hidden');

    AnimationUtils.showNotification(`🚀 Starting ${taskId.toUpperCase()} episode...`, 'blue', 2000);

    try {
      const obs = await this.api.reset(taskId);
      this.currentObs = obs;
      this.episodeRunning = true;
      this.currentStepIndex = 0;
      this.episodeStartTime = Date.now();
      this.prevAlertIds = new Set();

      // Start timer
      if (this.timerInterval) clearInterval(this.timerInterval);
      this.timerInterval = setInterval(() => this._updateTimer(), 1000);

      // Build demo action sequence from initial observation
      this.demoActions = this.buildDemoActions(obs);

      // Initial UI update (staggered alerts)
      this._resetUIForEpisode();
      this._updateHeader(obs);
      this._updatePhase(0, obs.max_steps);
      await this._populateInitialAlerts(obs.alert_queue);
      this._updateNetworkTopology(obs.network_topology);
      this._updateBusinessImpact(obs.business_impact_score);
      this._updateActiveThreats(obs.active_threats);
      this._updateContainmentProgress(obs, taskId);

      // Populate threat graph from initial observation
      this.threatGraph = new ClientThreatGraph();
      this.threatGraph.updateFromObservation(obs, null);
      obs.alert_queue.forEach(a => this.prevAlertIds.add(a.alert_id));
      this.graphViz.update(this.threatGraph.getGraphData());

      // Start auto-play
      this._scheduleNextStep(2500);

    } catch (err) {
      console.error('Episode start failed:', err);
      AnimationUtils.showNotification(`❌ Failed to start episode: ${err.message}`, 'red', 5000);
      document.getElementById('btn-start').classList.remove('hidden');
      document.getElementById('task-select').disabled = false;
      document.getElementById('btn-pause').classList.add('hidden');
      document.getElementById('btn-next').classList.add('hidden');
      document.getElementById('btn-reset').classList.add('hidden');
    }
  }

  buildDemoActions(obs) {
    // Parse initial observation to get real data
    const alerts = obs.alert_queue || [];
    const alertIds = alerts.map(a => a.alert_id);
    const taskId = obs.task_id;

    // Collect all IOCs from alerts
    const allIocs = [];
    const ipIocs = [];
    const domainIocs = [];
    const hashIocs = [];
    const hostsSeen = new Set();
    const subnetsSeen = new Set();

    alerts.forEach(a => {
      if (!hostsSeen.has(a.source_host)) {
        hostsSeen.add(a.source_host);
      }
      if (a.subnet) subnetsSeen.add(a.subnet);
      (a.ioc_indicators || []).forEach(ioc => {
        if (!allIocs.includes(ioc)) {
          allIocs.push(ioc);
          if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ioc)) ipIocs.push(ioc);
          else if (/[a-f0-9]{32,64}/i.test(ioc)) hashIocs.push(ioc);
          else domainIocs.push(ioc);
        }
      });
    });

    const hosts = [...hostsSeen];
    const firstHost = hosts[0] || 'WS-042';
    const secondHost = hosts[1] || firstHost;
    const thirdHost = hosts[2] || firstHost;
    const firstIp = ipIocs[0] || allIocs[0] || '192.168.1.1';
    const firstDomain = domainIocs[0] || allIocs[1] || firstIp;
    const firstHash = hashIocs[0] || allIocs[2] || firstIp;

    // Task-specific action sequences using known data
    if (taskId === 'hard') {
      return this._hardDemoActions(alertIds, hosts, ipIocs, domainIocs, hashIocs);
    } else if (taskId === 'medium') {
      return this._mediumDemoActions(alertIds, hosts, ipIocs, domainIocs, hashIocs);
    } else {
      return this._easyDemoActions(alertIds, hosts, ipIocs, domainIocs, hashIocs);
    }
  }

  _hardDemoActions(alertIds, hosts, ipIocs, domainIocs, hashIocs) {
    return [
      // TRIAGE: correlate alerts about the C2 activity
      { type: 'correlate_alerts', alert_ids: [alertIds[0] || 'ALERT-H001', alertIds[1] || 'ALERT-H002'] },

      // INVESTIGATION: executive host (entry point)
      { type: 'query_host', hostname: 'EXEC-003' },
      { type: 'run_forensics', hostname: 'EXEC-003' },

      // INVESTIGATION: corporate host with C2 beacon
      { type: 'query_host', hostname: 'WS-088' },
      { type: 'run_forensics', hostname: 'WS-088' },

      // THREAT INTEL: enrich the C2 IP
      { type: 'enrich_ioc', ioc_value: ipIocs[0] || '198.51.100.77', ioc_type: 'ip' },

      // INVESTIGATION: datacenter server (privilege escalation target)
      { type: 'scan_host_vulnerabilities', hostname: 'SRV-002' },
      { type: 'run_forensics', hostname: 'SRV-002' },

      // REMEDIATION: kill C2-related processes
      { type: 'kill_process', hostname: 'EXEC-003', process_name: 'outlook_macro.exe' },
      { type: 'kill_process', hostname: 'EXEC-003', process_name: 'svchost_c2.exe' },
      { type: 'kill_process', hostname: 'WS-088', process_name: 'svchost_c2.exe' },

      // REMEDIATION: block C2 infrastructure
      { type: 'block_ioc', ioc_value: ipIocs[0] || '198.51.100.77', ioc_type: 'ip' },
      { type: 'block_ioc', ioc_value: domainIocs[0] || 'cdn-update.malware-c2.net', ioc_type: 'domain' },

      // REMEDIATION: isolate executive subnet (triggers pivot if adaptive=true)
      { type: 'isolate_segment', subnet: 'executive', reason: 'APT lateral movement detected — executive subnet compromised' },

      // REMEDIATION: SOAR playbook for C2 disruption
      { type: 'trigger_playbook', playbook_name: 'c2_disruption', target: 'EXEC-003' },

      // REMEDIATION: kill exfil and ransomware processes
      { type: 'kill_process', hostname: 'SRV-002', process_name: 'exploit_kernel.exe' },
      { type: 'kill_process', hostname: 'SRV-002', process_name: 'data_pump.exe' },
      { type: 'kill_process', hostname: 'FIN-008', process_name: 'data_pump.exe' },
      { type: 'kill_process', hostname: 'SRV-010', process_name: 'blackcat_ransom.exe' },

      // REPORT: submit comprehensive containment plan
      {
        type: 'submit_containment_plan',
        plan: [
          {
            threat_id: 'T-HARD-001',
            actions_taken: ['query_host', 'run_forensics', 'kill_process', 'correlate_alerts'],
            root_cause: 'Spear-phishing email with malicious macro attachment targeting executive VP. Macro executed outlook_macro.exe establishing initial foothold.',
            confidence: 0.95,
          },
          {
            threat_id: 'T-HARD-002',
            actions_taken: ['run_forensics', 'kill_process', 'block_ioc', 'trigger_playbook', 'isolate_segment'],
            root_cause: 'C2 beacon (svchost_c2.exe) established on EXEC-003 and WS-088 communicating to 198.51.100.77 every 60s. C2 infrastructure disrupted.',
            confidence: 0.92,
          },
          {
            threat_id: 'T-HARD-003',
            actions_taken: ['scan_host_vulnerabilities', 'run_forensics', 'kill_process'],
            root_cause: 'Kernel privilege escalation on SRV-002 via exploit_kernel.exe. CVE leveraged for SYSTEM-level access to database server.',
            confidence: 0.88,
          },
          {
            threat_id: 'T-HARD-004',
            actions_taken: ['run_forensics', 'kill_process', 'block_ioc'],
            root_cause: 'Data exfiltration campaign using data_pump.exe on SRV-002 and FIN-008. 2.3GB customer PII transferred to 203.0.113.99. Exfil channel blocked.',
            confidence: 0.90,
          },
          {
            threat_id: 'T-HARD-005',
            actions_taken: ['kill_process'],
            root_cause: 'BlackCat ransomware deployment on datacenter servers SRV-010 and SRV-015. Encryption halted before full deployment. Recovery recommended.',
            confidence: 0.85,
          },
        ],
        executive_summary: 'APT campaign fully contained. C2 infrastructure at 198.51.100.77 disrupted and blocked. Executive subnet isolated. All 5 threat chains neutralized: phishing entry point, C2 beaconing, kernel privilege escalation, data exfiltration, and ransomware deployment. Estimated data exposure: 2.3GB PII. Recommend: patch SRV-002 kernel CVE, reset all executive credentials, deploy EDR signatures for BlackCat variants.',
      },
    ];
  }

  _mediumDemoActions(alertIds, hosts, ipIocs, domainIocs, hashIocs) {
    return [
      { type: 'correlate_alerts', alert_ids: alertIds.slice(0, 2) },
      { type: 'query_host', hostname: hosts[0] || 'WS-017' },
      { type: 'run_forensics', hostname: hosts[0] || 'WS-017' },
      { type: 'enrich_ioc', ioc_value: domainIocs[0] || ipIocs[0] || '203.0.113.50', ioc_type: domainIocs.length > 0 ? 'domain' : 'ip' },
      { type: 'query_host', hostname: hosts[1] || 'DEV-033' },
      { type: 'run_forensics', hostname: hosts[1] || 'DEV-033' },
      { type: 'kill_process', hostname: hosts[0] || 'WS-017', process_name: 'powershell.exe' },
      { type: 'kill_process', hostname: hosts[0] || 'WS-017', process_name: 'mimikatz.exe' },
      { type: 'block_ioc', ioc_value: domainIocs[0] || ipIocs[0] || '203.0.113.50', ioc_type: domainIocs.length > 0 ? 'domain' : 'ip' },
      { type: 'kill_process', hostname: hosts[1] || 'DEV-033', process_name: 'svchost_backdoor.exe' },
      { type: 'isolate_segment', subnet: 'corporate', reason: 'Credential theft and lateral movement detected' },
      { type: 'trigger_playbook', playbook_name: 'phishing_response', target: hosts[0] || 'WS-017' },
      {
        type: 'submit_containment_plan',
        plan: [
          { threat_id: 'T-MED-001', actions_taken: ['query_host', 'run_forensics', 'kill_process'], root_cause: 'Phishing email led to PowerShell execution downloading payload from evil-login.example.com', confidence: 0.9 },
          { threat_id: 'T-MED-002', actions_taken: ['run_forensics', 'kill_process', 'block_ioc'], root_cause: 'Credential dumping via Mimikatz. LSASS memory access detected.', confidence: 0.88 },
          { threat_id: 'T-MED-003', actions_taken: ['run_forensics', 'kill_process', 'isolate_segment'], root_cause: 'Lateral movement via compromised admin credentials to DEV-033 and FIN-012', confidence: 0.85 },
        ],
        executive_summary: 'Multi-stage phishing → credential theft → lateral movement campaign contained. Three compromised hosts remediated. Corporate subnet isolated pending investigation.',
      },
    ];
  }

  _easyDemoActions(alertIds, hosts, ipIocs, domainIocs, hashIocs) {
    const host = hosts[0] || 'WS-042';
    const hash = hashIocs[0] || ipIocs[0] || 'e99a18c428cb38d5f260853678922e03';
    return [
      { type: 'correlate_alerts', alert_ids: alertIds.slice(0, 2) },
      { type: 'query_host', hostname: host },
      { type: 'run_forensics', hostname: host },
      { type: 'enrich_ioc', ioc_value: hash, ioc_type: hashIocs.length > 0 ? 'hash' : 'ip' },
      { type: 'kill_process', hostname: host, process_name: 'cryptolocker.exe' },
      { type: 'block_ioc', ioc_value: hash, ioc_type: hashIocs.length > 0 ? 'hash' : 'ip' },
      { type: 'scan_host_vulnerabilities', hostname: host },
      { type: 'trigger_playbook', playbook_name: 'ransomware_containment', target: host },
      {
        type: 'submit_containment_plan',
        plan: [{
          threat_id: 'T-EASY-001',
          actions_taken: ['query_host', 'run_forensics', 'kill_process', 'block_ioc'],
          root_cause: 'Ransomware (cryptolocker.exe) executing on WS-042, encrypting user documents. Delivered via phishing email attachment.',
          confidence: 0.95,
        }],
        executive_summary: 'Single ransomware endpoint contained. Process killed, IOC hash blocked. Recommend disk restore from backup for WS-042.',
      },
    ];
  }

  // ============================================================
  // Step Execution
  // ============================================================

  _scheduleNextStep(delay = 2000) {
    if (this.isPaused || !this.episodeRunning) return;
    if (this.autoPlayTimer) clearTimeout(this.autoPlayTimer);
    this.autoPlayTimer = setTimeout(() => this._executeNextStep(), delay);
  }

  async _executeNextStep() {
    if (!this.episodeRunning || this.currentObs?.done) {
      this.episodeRunning = false;
      return;
    }
    if (this.currentStepIndex >= this.demoActions.length) {
      AnimationUtils.showNotification('ℹ️ Demo sequence complete. Episode still running.', 'blue', 3000);
      return;
    }

    const action = this.demoActions[this.currentStepIndex];
    this.currentAction = action;
    this.currentStepIndex++;

    try {
      const obs = await this.api.step(action);
      this.currentObs = obs;
      await this.updateUI(obs, action);

      if (obs.done) {
        this.episodeRunning = false;
        if (this.timerInterval) clearInterval(this.timerInterval);
        this._handleEpisodeComplete(obs);
      } else if (!this.isPaused) {
        // Adjust delay based on action type for dramatic effect
        let delay = 2000;
        if (action.type === 'isolate_segment') delay = 3000; // Longer for pivot drama
        if (action.type === 'submit_containment_plan') delay = 500;
        this._scheduleNextStep(delay);
      }
    } catch (err) {
      console.error('Step failed:', err);
      AnimationUtils.showNotification(`❌ Step failed: ${err.message.substring(0, 80)}`, 'red', 4000);
      // Try to continue on error
      if (!this.isPaused) this._scheduleNextStep(3000);
    }
  }

  // ============================================================
  // UI Updates
  // ============================================================

  async updateUI(obs, action) {
    this._updateHeader(obs);
    this._updatePhase(obs.step_count, obs.max_steps);
    this._updateActionLog(obs.timeline, action, obs);
    this._updateNetworkTopology(obs.network_topology);
    this._updateBusinessImpact(obs.business_impact_score);
    this._updateActiveThreats(obs.active_threats);
    this._updateContainmentProgress(obs, obs.task_id);
    this._updateRewardBadge(obs.total_reward);

    // Check for new pivot alerts
    const newPivots = [];
    (obs.alert_queue || []).forEach(alert => {
      if (alert.alert_id.startsWith('PIVOT-') && !this.prevAlertIds.has(alert.alert_id)) {
        newPivots.push(alert);
      }
    });

    // Update alert queue (add new alerts with animation)
    await this._updateAlertQueue(obs.alert_queue, newPivots.length > 0);

    // Update threat graph
    this.threatGraph.updateFromObservation(obs, action);
    this.graphViz.update(this.threatGraph.getGraphData());

    // Animate forensics result on graph
    if (action?.type === 'run_forensics' && obs.host_forensics) {
      this.graphViz.flashNode(obs.host_forensics.hostname, obs.host_forensics.is_compromised ? 'red' : 'green');
    }
    if (action?.type === 'block_ioc') {
      this.graphViz.flashNode(action.ioc_value, 'green');
    }
    if (action?.type === 'kill_process') {
      const procId = `${action.hostname}:${action.process_name}`;
      this.graphViz.flashNode(procId, 'green');
      AnimationUtils.showNotification(`💀 Killed: ${action.process_name} on ${action.hostname}`, 'amber', 2000);
    }

    // Red Team pivot moment
    if (newPivots.length > 0) {
      this._handleRedTeamPivot(newPivots[0]);
      newPivots.forEach(p => {
        this.prevAlertIds.add(p.alert_id);
        // Animate pivot edge in graph
        const pivotLinks = this.threatGraph.links.filter(l => l.edgeType === 'pivoted_from');
        if (pivotLinks.length > 0) {
          const pl = pivotLinks[pivotLinks.length - 1];
          const srcId = pl.source.id || pl.source;
          const tgtId = pl.target.id || pl.target;
          this.graphViz.animatePivot(srcId, tgtId);
        }
      });
    }

    // Update reward timeline chart
    if (obs.step_count > 0) {
      this.rewardTimeline.addPoint(obs.step_count, obs.total_reward, action?.type);
    }

    // Update threat graph summary subtitle
    if (obs.threat_graph_summary) this._updateGraphSummary(obs.threat_graph_summary);

    // Update live score estimates
    this._updateLiveScores(obs, action);

    // Sync alert IDs
    (obs.alert_queue || []).forEach(a => this.prevAlertIds.add(a.alert_id));
  }

  _updateLiveScores(obs, action) {
    if (!action) return;
    const scores = { ...this.liveScores };

    if (action.type === 'correlate_alerts') scores.siem_correlation = 1.0;
    if (action.type === 'run_forensics') {
      scores.forensic_investigation = Math.min(1, scores.forensic_investigation + 0.2);
    }
    if (action.type === 'enrich_ioc') {
      scores.threat_intel_usage = Math.min(1, scores.threat_intel_usage + 0.25);
    }
    if (action.type === 'scan_host_vulnerabilities' && obs.vulnerability_results?.length > 0) {
      scores.vuln_root_cause = 1.0;
    }
    if (action.type === 'block_ioc') {
      scores.ioc_blocking = Math.min(1, scores.ioc_blocking + 0.2);
    }
    if (action.type === 'kill_process') {
      scores.threat_containment = Math.min(1, scores.threat_containment + 0.15);
    }
    if (action.type === 'submit_containment_plan') {
      scores.plan_coverage = 0.9;
      scores.plan_evidence_quality = 0.85;
    }

    // Business impact inversely related to actual business_impact_score
    scores.business_impact = Math.max(0, 1.0 - obs.business_impact_score);

    // Step efficiency based on step count vs max
    const ratio = obs.step_count / (obs.max_steps || 30);
    scores.step_efficiency = Math.max(0.3, 1.0 - Math.max(0, ratio - 0.5) * 1.5);

    this.liveScores = scores;
    this.radarChart.update(scores);
  }

  _updateHeader(obs) {
    const stepEl = document.getElementById('header-step');
    const episodeEl = document.getElementById('header-episode');
    const diffBadge = document.getElementById('difficulty-badge');

    if (stepEl) {
      const old = parseInt(stepEl.textContent.split('/')[0]) || 0;
      AnimationUtils.countUpInt(stepEl, old, obs.step_count, 300);
      // Reformat with max_steps after animation
      setTimeout(() => {
        if (stepEl) stepEl.textContent = `${obs.step_count}/${obs.max_steps}`;
      }, 350);
    }

    if (episodeEl && obs.episode_id) {
      episodeEl.textContent = obs.episode_id.substring(0, 8) + '…';
    }

    if (diffBadge && obs.task_id) {
      diffBadge.textContent = obs.task_id.toUpperCase();
      diffBadge.className = `difficulty-badge ${obs.task_id}`;
    }
  }

  _updateTimer() {
    if (!this.episodeStartTime) return;
    const elapsed = Math.floor((Date.now() - this.episodeStartTime) / 1000);
    const mm = String(Math.floor(elapsed / 60)).padStart(2, '0');
    const ss = String(elapsed % 60).padStart(2, '0');
    const el = document.getElementById('header-timer');
    if (el) el.textContent = `${mm}:${ss}`;
  }

  _updatePhase(step, maxSteps) {
    // Phase progression based on step count and action types
    const dots = document.querySelectorAll('.phase-dot');
    const connectors = document.querySelectorAll('.phase-connector');

    // Determine current phase
    let phaseIdx = 0;
    if (this.currentAction) {
      const t = this.currentAction.type;
      if (['correlate_alerts'].includes(t)) phaseIdx = 0; // TRIAGE
      else if (['query_host', 'run_forensics', 'enrich_ioc', 'scan_host_vulnerabilities'].includes(t)) phaseIdx = 1; // INVESTIGATION
      else if (['kill_process', 'block_ioc', 'isolate_segment', 'trigger_playbook'].includes(t)) phaseIdx = 2; // REMEDIATION
      else if (['submit_containment_plan'].includes(t)) phaseIdx = 3; // REPORT
    }

    dots.forEach((dot, i) => {
      dot.classList.remove('active', 'completed');
      if (i < phaseIdx) dot.classList.add('completed');
      else if (i === phaseIdx) dot.classList.add('active');
    });

    connectors.forEach((conn, i) => {
      conn.classList.toggle('completed', i < phaseIdx);
    });
  }

  async _populateInitialAlerts(alerts) {
    const list = document.getElementById('alert-list');
    if (!list) return;
    list.innerHTML = '';

    // Stagger alert cards sliding in
    for (let i = 0; i < alerts.length; i++) {
      await new Promise(r => setTimeout(r, 180 * i));
      this._addAlertCard(alerts[i], list, false);
    }

    this._updateAlertBadge(alerts.length);
  }

  async _updateAlertQueue(alerts, hasPivot = false) {
    const list = document.getElementById('alert-list');
    if (!list) return;

    // Find new alerts
    const existingIds = new Set([...list.querySelectorAll('.alert-card')].map(c => c.dataset.alertId));
    const newAlerts = alerts.filter(a => !existingIds.has(a.alert_id));

    newAlerts.forEach(alert => {
      this._addAlertCard(alert, list, alert.alert_id.startsWith('PIVOT-'));
    });

    // Update resolved state
    const resolvedCount = alerts.filter(a => a.is_acknowledged).length;
    this._updateAlertBadge(alerts.length - resolvedCount);
  }

  _addAlertCard(alert, container, isPivot = false) {
    const card = document.createElement('div');
    card.className = `alert-card${isPivot ? ' pivot' : ''}`;
    card.dataset.alertId = alert.alert_id;

    const severityClass = `severity-${alert.severity}`;
    const iocText = (alert.ioc_indicators || []).join(', ');
    const iocHtml = iocText ? `<div class="alert-iocs">IOCs: ${iocText}</div>` : '';
    const pivotBadge = isPivot ? `<span class="pivot-badge">⚡ PIVOT</span>` : '';
    const correlBadge = alert.is_acknowledged ? `<span class="correlated-badge">🔗 CORR</span>` : '';

    card.innerHTML = `
      <div class="alert-card-header">
        <span class="${severityClass} severity-badge">${alert.severity.toUpperCase()}</span>
        <span class="alert-host">${alert.source_host}</span>
      </div>
      <div class="alert-description">${alert.description}</div>
      ${iocHtml}
      <div class="alert-footer">
        <span style="font-size:9px;color:var(--text-muted);font-family:monospace">${alert.threat_type}</span>
        ${pivotBadge}${correlBadge}
      </div>
    `;

    card.title = alert.description;
    container.insertBefore(card, container.firstChild);
  }

  _updateAlertBadge(count) {
    const badge = document.getElementById('alert-count-badge');
    if (badge) badge.textContent = count;
  }

  _updateActionLog(timeline, lastAction, obs) {
    const log = document.getElementById('action-log');
    if (!log || !timeline?.length) return;

    const lastEntry = timeline[timeline.length - 1];
    if (!lastEntry) return;

    // Remove empty state
    const empty = log.querySelector('.empty-state');
    if (empty) empty.remove();

    const category = this._getActionCategory(lastEntry.action_type);
    const isPos = lastEntry.reward >= 0;
    const rewardText = `${isPos ? '+' : ''}${lastEntry.reward.toFixed(2)}`;
    const rewardClass = isPos ? 'positive' : 'negative';
    const icon = this._getActionIcon(lastEntry.action_type);

    const detailsHtml = this._buildLogDetails(lastEntry.action_type, obs);

    const entry = document.createElement('div');
    entry.className = `log-entry ${category}`;
    entry.innerHTML = `
      <div>
        <span class="log-step">[Step ${String(lastEntry.step).padStart(2, '0')}]</span>
        <span class="log-action"> ${icon} ${lastEntry.action_type}</span>
        <span class="log-target"> → ${lastEntry.target}</span>
        <span class="log-reward ${rewardClass}" style="float:right">${isPos ? '✅' : '❌'} ${rewardText}</span>
      </div>
      <div class="log-result">${lastEntry.result.substring(0, 120)}</div>
      ${detailsHtml}
    `;

    log.insertBefore(entry, log.firstChild);

    // Update total reward badge
    this._updateRewardBadge(obs?.total_reward ?? 0);
  }

  _buildLogDetails(actionType, obs) {
    if (!obs) return '';
    const lines = [];

    if (actionType === 'run_forensics' && obs.host_forensics) {
      const f = obs.host_forensics;
      const status = f.is_compromised
        ? `<span style="color:var(--accent-red)">⚠ COMPROMISED</span>`
        : `<span style="color:var(--accent-green)">✓ CLEAN</span>`;
      lines.push(`Status: ${status}`);
      if (f.malicious_processes?.length) {
        lines.push(`Procs: <span style="color:var(--accent-amber)">${f.malicious_processes.join(' · ')}</span>`);
      }
      if (f.network_connections?.length) {
        lines.push(`Conns: <span style="color:var(--accent-red)">${f.network_connections.slice(0, 3).join(' · ')}</span>`);
      }
    }

    if (actionType === 'enrich_ioc' && obs.ioc_enrichment) {
      const e = obs.ioc_enrichment;
      if (e.threat_actor) lines.push(`Actor: <span style="color:var(--accent-red)">${e.threat_actor}</span>`);
      if (e.reputation !== undefined) lines.push(`Reputation: <span style="color:var(--accent-amber)">${e.reputation}</span>`);
      if (e.mitre_ttps?.length) lines.push(`TTPs: <span style="color:var(--accent-purple)">${e.mitre_ttps.slice(0, 3).join(' · ')}</span>`);
    }

    if (actionType === 'scan_host_vulnerabilities' && obs.vulnerability_results?.length) {
      const vulns = obs.vulnerability_results;
      const critical = vulns.filter(v => v.cvss_score >= 9).length;
      const cves = vulns.slice(0, 3).map(v => v.cve_id).join(' · ');
      lines.push(`Found ${vulns.length} CVEs${critical ? ` (<span style="color:var(--accent-red)">${critical} critical</span>)` : ''}`);
      if (cves) lines.push(`<span style="color:var(--accent-amber)">${cves}</span>`);
    }

    if (actionType === 'trigger_playbook' && obs.playbook_result) {
      const p = obs.playbook_result;
      const success = p.success ?? p.status === 'success';
      lines.push(`Result: <span style="color:${success ? 'var(--accent-green)' : 'var(--accent-red)'}">
        ${success ? '✓ Executed' : '✗ Failed'}</span>`);
      if (p.actions_taken?.length) lines.push(`Steps: ${p.actions_taken.slice(0, 3).join(' → ')}`);
    }

    if (actionType === 'correlate_alerts' && obs.correlation_results) {
      const c = obs.correlation_results;
      const count = Array.isArray(c) ? c.length : (c.correlated_count ?? 1);
      lines.push(`Correlated <span style="color:var(--accent-purple)">${count} alerts</span> into chain`);
      if (c.threat_chain) lines.push(`Chain: <span style="color:var(--accent-cyan)">${c.threat_chain}</span>`);
    }

    if (!lines.length) return '';
    return `<div class="log-details">${lines.join('<br>')}</div>`;
  }

  _updateGraphSummary(summary) {
    const el = document.getElementById('graph-summary');
    if (el && summary) el.textContent = summary;
  }

  _updateRewardBadge(totalReward) {
    const badge = document.getElementById('total-reward-badge');
    if (!badge) return;
    const isPos = totalReward >= 0;
    badge.textContent = `${isPos ? '+' : ''}${totalReward.toFixed(2)}`;
    badge.className = `reward-badge${isPos ? '' : ' negative'}`;
    AnimationUtils.scaleBounce(badge);
  }

  _updateNetworkTopology(topology) {
    const container = document.getElementById('network-topology');
    if (!container) return;

    const subnetConfig = {
      corporate:   { label: 'Corporate',   color: '#3b82f6' },
      engineering: { label: 'Engineering', color: '#06b6d4' },
      finance:     { label: 'Finance',     color: '#f59e0b' },
      dmz:         { label: 'DMZ',         color: '#94a3b8' },
      datacenter:  { label: 'Datacenter',  color: '#8b5cf6' },
      executive:   { label: 'Executive',   color: '#ef4444' },
    };

    // Build or update subnet section skeletons
    Object.entries(topology.subnets || {}).forEach(([subnet, count]) => {
      const cfg = subnetConfig[subnet] || { label: subnet, color: '#94a3b8' };
      let section = document.getElementById(`subnet-${subnet}`);
      if (!section) {
        section = document.createElement('div');
        section.className = 'subnet-section';
        section.id = `subnet-${subnet}`;
        section.innerHTML = `
          <div class="subnet-header">
            <span class="subnet-name" style="color:${cfg.color}">${cfg.label}</span>
            <span class="subnet-stats" id="stats-${subnet}">${count} hosts</span>
          </div>
          <div class="host-grid" id="grid-${subnet}"></div>
        `;
        container.appendChild(section);
      }

      // Populate grid with placeholder dots (count-based, no known names yet)
      const grid = document.getElementById(`grid-${subnet}`);
      if (grid && grid.children.length === 0) {
        for (let i = 0; i < count; i++) {
          const dot = document.createElement('div');
          dot.className = 'host-dot online';
          dot.dataset.idx = i;
          grid.appendChild(dot);
        }
      }
    });

    // Overlay known-host statuses from the threat graph onto the dots
    // Group graph hosts by subnet
    const subnetHostStatus = {};  // subnet -> [{hostname, status}]
    this.threatGraph.nodes.forEach((node) => {
      if (node.nodeType !== 'host' || !node.subnet) return;
      if (!subnetHostStatus[node.subnet]) subnetHostStatus[node.subnet] = [];
      subnetHostStatus[node.subnet].push({ hostname: node.id, status: node.status || 'online' });
    });

    // For each subnet, update the first N dots with known statuses
    Object.entries(subnetHostStatus).forEach(([subnet, hosts]) => {
      const grid = document.getElementById(`grid-${subnet}`);
      if (!grid) return;
      const dots = [...grid.querySelectorAll('.host-dot')];
      hosts.forEach((h, i) => {
        if (i < dots.length) {
          dots[i].className = `host-dot ${h.status}`;
          dots[i].title = `${h.hostname} [${h.status}]`;
          dots[i].id = `hostdot-${h.hostname}`;
        }
      });
    });

    // Update header stats
    const topoStatComp = document.getElementById('topo-compromised');
    const topoStatIso = document.getElementById('topo-isolated');
    if (topoStatComp) topoStatComp.textContent = `${topology.compromised_count} compromised`;
    if (topoStatIso) topoStatIso.textContent = `${topology.isolated_count} isolated`;

    // Mark isolated subnets
    Object.keys(topology.subnets || {}).forEach(subnet => {
      const section = document.getElementById(`subnet-${subnet}`);
      if (!section) return;
      const hosts = subnetHostStatus[subnet] || [];
      const isIsolated = hosts.some(h => h.status === 'isolated');
      const hasCompromised = hosts.some(h => h.status === 'compromised');
      section.classList.toggle('isolated', isIsolated);
      section.classList.toggle('has-compromised', hasCompromised && !isIsolated);

      let overlay = section.querySelector('.isolated-overlay');
      if (isIsolated && !overlay) {
        overlay = document.createElement('div');
        overlay.className = 'isolated-overlay';
        overlay.textContent = '🔒 ISOLATED';
        section.appendChild(overlay);
      } else if (!isIsolated && overlay) {
        overlay.remove();
      }
    });
  }

  _updateBusinessImpact(score) {
    const marker = document.getElementById('impact-marker');
    const value = document.getElementById('impact-value');
    if (marker) marker.style.left = `${score * 100}%`;
    if (value) {
      const prev = parseFloat(value.textContent) || 0;
      AnimationUtils.countUp(value, prev, score, 400, 2);
      value.className = 'impact-value mono' + (score > 0.6 ? ' critical' : score > 0.35 ? ' high' : '');
    }

    if (score > 0.5) {
      const impactSection = document.querySelector('.impact-section');
      if (impactSection) AnimationUtils.pulseGlow(impactSection, score > 0.7 ? 'red' : 'amber', 2);
    }
  }

  _updateActiveThreats(threats) {
    const list = document.getElementById('active-threats-list');
    if (!list) return;
    if (!threats || threats.length === 0) {
      list.innerHTML = '<span style="color:var(--accent-green);font-size:11px;">✅ All threats contained</span>';
      return;
    }
    list.innerHTML = threats.map(t => `<span class="threat-tag">${t}</span>`).join('');
  }

  _updateContainmentProgress(obs, taskId) {
    const container = document.getElementById('containment-bars');
    if (!container) return;

    // Derive progress from timeline
    const timeline = obs.timeline || [];
    const killed = timeline.filter(t => t.action_type === 'kill_process');
    const blocked = timeline.filter(t => t.action_type === 'block_ioc');
    const forensics = timeline.filter(t => t.action_type === 'run_forensics');
    const playbooks = timeline.filter(t => t.action_type === 'trigger_playbook');
    const correlated = timeline.some(t => t.action_type === 'correlate_alerts');

    // Task-specific totals
    const totals = {
      hard:   { kill: 8, block: 6, forensics: 5, playbooks: 1 },
      medium: { kill: 4, block: 5, forensics: 3, playbooks: 1 },
      easy:   { kill: 1, block: 1, forensics: 1, playbooks: 1 },
    };
    const t = totals[taskId] || totals.hard;

    const bars = [
      { id: 'bar-kill', label: 'Processes Killed', current: Math.min(killed.length, t.kill), total: t.kill },
      { id: 'bar-block', label: 'IOCs Blocked', current: Math.min(blocked.length, t.block), total: t.block },
      { id: 'bar-forensics', label: 'Hosts Investigated', current: Math.min(forensics.length, t.forensics), total: t.forensics },
      { id: 'bar-playbooks', label: 'Playbooks Triggered', current: Math.min(playbooks.length, t.playbooks), total: t.playbooks },
    ];

    bars.forEach(bar => {
      let item = document.getElementById(bar.id);
      if (!item) {
        item = document.createElement('div');
        item.id = bar.id;
        item.className = 'containment-bar-item';
        container.appendChild(item);
      }
      const pct = bar.total > 0 ? Math.round((bar.current / bar.total) * 100) : 0;
      const isComplete = bar.current >= bar.total;
      item.innerHTML = `
        <div class="containment-bar-label">
          <span>${bar.label}</span>
          <span class="${isComplete ? 'complete' : ''}">${bar.current}/${bar.total}${isComplete ? ' ✓' : ''}</span>
        </div>
        <div class="containment-bar-track">
          <div class="containment-bar-fill ${isComplete ? 'complete' : ''}" style="width:${pct}%"></div>
        </div>
      `;
    });
  }

  _handleRedTeamPivot(pivotAlert) {
    AnimationUtils.triggerRedTeamPivot();
    // Add the pivot alert to the queue with special styling
    const list = document.getElementById('alert-list');
    if (list) {
      const card = document.createElement('div');
      card.className = 'alert-card pivot';
      card.dataset.alertId = pivotAlert.alert_id;
      card.innerHTML = `
        <div class="alert-card-header">
          <span class="severity-critical severity-badge">CRITICAL</span>
          <span class="alert-host">${pivotAlert.source_host || 'UNKNOWN'}</span>
        </div>
        <div class="alert-description" style="color:var(--accent-red)">⚡ ADAPTIVE THREAT — LATERAL PIVOT DETECTED. Adversary moved to new host.</div>
        <div class="alert-footer">
          <span class="pivot-badge">⚡ PIVOT</span>
        </div>
      `;
      list.insertBefore(card, list.firstChild);
    }
    // Recalculate containment (requirements grew)
    AnimationUtils.showNotification('⚡ Red Team lateral pivot! Containment requirements updated.', 'red', 5000);
  }

  _handleEpisodeComplete(obs) {
    if (this.timerInterval) clearInterval(this.timerInterval);
    document.getElementById('btn-pause').classList.add('hidden');
    document.getElementById('btn-next').classList.add('hidden');

    // Update phase to REPORT
    this.currentAction = { type: 'submit_containment_plan' };
    this._updatePhase(obs.step_count, obs.max_steps);

    // Update radar with final scores
    if (obs.grade_breakdown) {
      this.radarChart.update(obs.grade_breakdown);
    }

    // Brief delay then show final score overlay
    setTimeout(() => {
      const finalScore = obs.final_score ?? obs.total_reward ?? 0;
      AnimationUtils.revealFinalScore(
        finalScore,
        obs.grade_breakdown,
        [], // penalties would come from grade_result
        []  // bonuses
      );
      AnimationUtils.showNotification(`🏆 Episode complete! Score: ${finalScore.toFixed(3)}`, 'green', 6000);
    }, 1000);
  }

  // ============================================================
  // Helpers
  // ============================================================

  _getActionCategory(actionType) {
    if (['correlate_alerts'].includes(actionType)) return 'triage';
    if (['query_host', 'run_forensics', 'enrich_ioc', 'scan_host_vulnerabilities'].includes(actionType)) return 'investigation';
    if (['kill_process', 'block_ioc', 'isolate_segment', 'trigger_playbook'].includes(actionType)) return 'remediation';
    if (['submit_containment_plan'].includes(actionType)) return 'report';
    return 'investigation';
  }

  _getActionIcon(actionType) {
    const icons = {
      query_host: '🔍',
      run_forensics: '🧬',
      enrich_ioc: '🔎',
      scan_host_vulnerabilities: '🩺',
      kill_process: '⚔️',
      block_ioc: '🚫',
      isolate_segment: '🔒',
      trigger_playbook: '▶️',
      correlate_alerts: '🔗',
      submit_containment_plan: '📝',
    };
    return icons[actionType] || '➤';
  }

  _showConnectionOverlay(msg) {
    const overlay = document.getElementById('connection-overlay');
    const status = document.getElementById('connection-status');
    if (overlay) overlay.classList.remove('hidden');
    if (status) status.textContent = msg;
  }

  _hideConnectionOverlay() {
    const overlay = document.getElementById('connection-overlay');
    if (overlay) {
      overlay.style.transition = 'opacity 0.5s ease';
      overlay.style.opacity = '0';
      setTimeout(() => {
        overlay.classList.add('hidden');
        overlay.style.opacity = '';
        overlay.style.transition = '';
      }, 500);
    }
  }

  _resetUI() {
    // Clear all panels to initial state
    document.getElementById('alert-list').innerHTML = '<div class="empty-state">Awaiting alerts...</div>';
    document.getElementById('action-log').innerHTML = '<div class="empty-state">Awaiting agent actions...</div>';
    document.getElementById('active-threats-list').innerHTML = '<span class="empty-state">No threats detected</span>';
    document.getElementById('containment-bars').innerHTML = '';
    document.getElementById('network-topology').innerHTML = '';
    document.getElementById('network-topology').dataset.built = 'false';
    document.getElementById('header-step').textContent = '0/30';
    document.getElementById('header-episode').textContent = '—';
    document.getElementById('header-timer').textContent = '00:00';
    document.getElementById('impact-value').textContent = '0.00';
    document.getElementById('impact-marker').style.left = '0%';
    document.getElementById('total-reward-badge').textContent = '+0.00';
    document.getElementById('alert-count-badge').textContent = '0';
    document.getElementById('difficulty-badge').textContent = '—';
    document.getElementById('difficulty-badge').className = 'difficulty-badge';

    // Reset phase
    document.querySelectorAll('.phase-dot').forEach(d => d.classList.remove('active', 'completed'));
    document.querySelectorAll('.phase-connector').forEach(c => c.classList.remove('completed'));

    // Reset charts
    if (this.rewardTimeline) this.rewardTimeline.reset();
    if (this.radarChart) this.radarChart.update({
      threat_containment: 0, ioc_blocking: 0, forensic_investigation: 0,
      siem_correlation: 0, threat_intel_usage: 0, vuln_root_cause: 0,
      business_impact: 1.0, step_efficiency: 0.5, plan_coverage: 0, plan_evidence_quality: 0,
    });

    // Reset threat graph
    this.threatGraph = new ClientThreatGraph();
    if (this.graphViz._initialized) {
      this.graphViz.update({ nodes: [], links: [] });
    }

    // Show start button
    document.getElementById('btn-start').classList.remove('hidden');
    document.getElementById('task-select').disabled = false;
  }

  _resetUIForEpisode() {
    document.getElementById('alert-list').innerHTML = '';
    document.getElementById('action-log').innerHTML = '';
    document.getElementById('containment-bars').innerHTML = '';
    document.getElementById('network-topology').innerHTML = '';
    document.getElementById('network-topology').dataset.built = 'false';
    if (this.rewardTimeline) this.rewardTimeline.reset();
    this.liveScores = {
      threat_containment: 0, ioc_blocking: 0, forensic_investigation: 0,
      siem_correlation: 0, threat_intel_usage: 0, vuln_root_cause: 0,
      business_impact: 1.0, step_efficiency: 0.5, plan_coverage: 0, plan_evidence_quality: 0,
    };
    if (this.radarChart) this.radarChart.update(this.liveScores);
  }

  closeScoreOverlay() {
    const overlay = document.getElementById('final-score-overlay');
    if (overlay) {
      overlay.style.transition = 'opacity 0.4s ease';
      overlay.style.opacity = '0';
      setTimeout(() => {
        overlay.classList.add('hidden');
        overlay.style.opacity = '';
      }, 400);
    }
  }
}


// ============================================================
// Bootstrap
// ============================================================
let dashboard;
document.addEventListener('DOMContentLoaded', () => {
  dashboard = new CyberSOCDashboard();
  window.dashboard = dashboard;
  dashboard.init();
});
