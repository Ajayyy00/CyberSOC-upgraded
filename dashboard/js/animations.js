/* ============================================================
   CyberSOC Dashboard — Animation Utilities
   ============================================================ */

const AnimationUtils = {
  _notifContainer: null,
  _flashEl: null,

  init() {
    // Notification container
    let nc = document.getElementById('notification-container');
    if (!nc) {
      nc = document.createElement('div');
      nc.id = 'notification-container';
      document.body.appendChild(nc);
    }
    this._notifContainer = nc;

    // Screen flash element
    let sf = document.getElementById('screen-flash');
    if (!sf) {
      sf = document.createElement('div');
      sf.id = 'screen-flash';
      sf.className = 'screen-flash';
      document.body.appendChild(sf);
    }
    this._flashEl = sf;
  },

  // Animate a number counting up/down
  countUp(element, from, to, duration = 600, decimals = 2) {
    if (!element) return;
    const start = performance.now();
    const range = to - from;
    const update = (now) => {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const ease = 1 - Math.pow(1 - progress, 3); // cubic ease-out
      const current = from + range * ease;
      element.textContent = current.toFixed(decimals);
      if (progress < 1) requestAnimationFrame(update);
    };
    requestAnimationFrame(update);
  },

  // Count up an integer (no decimals)
  countUpInt(element, from, to, duration = 400) {
    if (!element) return;
    const start = performance.now();
    const range = to - from;
    const update = (now) => {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const ease = 1 - Math.pow(1 - progress, 3);
      element.textContent = Math.round(from + range * ease);
      if (progress < 1) requestAnimationFrame(update);
    };
    requestAnimationFrame(update);
  },

  // Flash the screen border (for Red Team pivots)
  flashScreen(color = 'red', duration = 800) {
    if (!this._flashEl) return;
    this._flashEl.className = `screen-flash ${color}-flash`;
    this._flashEl.style.opacity = '1';
    setTimeout(() => {
      this._flashEl.style.transition = `opacity ${duration}ms ease`;
      this._flashEl.style.opacity = '0';
      setTimeout(() => {
        this._flashEl.style.transition = '';
        this._flashEl.className = 'screen-flash';
      }, duration);
    }, 150);
  },

  // Show a toast notification
  showNotification(text, type = 'blue', duration = 3000) {
    if (!this._notifContainer) return;
    const toast = document.createElement('div');
    toast.className = `notification-toast ${type}`;
    toast.textContent = text;
    this._notifContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      setTimeout(() => toast.remove(), 400);
    }, duration);
  },

  // Scale bounce for score changes
  scaleBounce(element, intensity = 1.12) {
    if (!element) return;
    element.style.transition = 'transform 0.15s ease';
    element.style.transform = `scale(${intensity})`;
    setTimeout(() => {
      element.style.transform = 'scale(1)';
    }, 150);
  },

  // Pulse glow on an element
  pulseGlow(element, color = 'blue', times = 3) {
    if (!element) return;
    const glowMap = {
      blue: '0 0 20px rgba(59,130,246,0.8)',
      red: '0 0 20px rgba(239,68,68,0.8)',
      green: '0 0 15px rgba(16,185,129,0.7)',
      amber: '0 0 15px rgba(245,158,11,0.7)',
      purple: '0 0 15px rgba(139,92,246,0.7)',
    };
    const glow = glowMap[color] || glowMap.blue;
    let count = 0;
    const pulse = () => {
      if (count >= times * 2) return;
      const isOn = count % 2 === 0;
      element.style.transition = 'box-shadow 0.3s ease';
      element.style.boxShadow = isOn ? glow : 'none';
      count++;
      setTimeout(pulse, 300);
    };
    pulse();
  },

  // Checkmark completion animation for progress bars
  checkmarkComplete(labelElement) {
    if (!labelElement) return;
    const check = document.createElement('span');
    check.textContent = ' ✓';
    check.style.color = 'var(--accent-green)';
    check.style.opacity = '0';
    check.style.transition = 'opacity 0.3s ease';
    labelElement.appendChild(check);
    requestAnimationFrame(() => {
      check.style.opacity = '1';
    });
  },

  // Reveal final score with dramatic animation
  revealFinalScore(finalScore, breakdown, penalties, bonuses) {
    const overlay = document.getElementById('final-score-overlay');
    if (!overlay) return;
    overlay.classList.remove('hidden');

    // Animate the main score number
    const scoreEl = document.getElementById('final-score-number');
    if (scoreEl) {
      scoreEl.textContent = '0.000';
      setTimeout(() => this.countUp(scoreEl, 0, finalScore, 1500, 3), 300);
    }

    // Build dimension bars
    const barsContainer = document.getElementById('final-grade-bars');
    if (barsContainer && breakdown) {
      barsContainer.innerHTML = '';
      const dimLabels = {
        threat_containment: 'Threat Containment',
        ioc_blocking: 'IOC Blocking',
        forensic_investigation: 'Forensic Investigation',
        siem_correlation: 'SIEM Correlation',
        threat_intel_usage: 'Threat Intel',
        vuln_root_cause: 'Vuln Root Cause',
        business_impact: 'Business Impact',
        step_efficiency: 'Step Efficiency',
        plan_coverage: 'Plan Coverage',
        plan_evidence_quality: 'Plan Evidence',
      };
      let delay = 500;
      Object.entries(breakdown).forEach(([key, value]) => {
        const item = document.createElement('div');
        item.className = 'final-grade-bar-item';
        item.innerHTML = `
          <span class="final-grade-bar-label">${dimLabels[key] || key}</span>
          <div class="final-grade-bar-track">
            <div class="final-grade-bar-fill" data-value="${value}" style="width:0%"></div>
          </div>
          <span class="final-grade-bar-value">0.00</span>
        `;
        barsContainer.appendChild(item);
        const fill = item.querySelector('.final-grade-bar-fill');
        const valEl = item.querySelector('.final-grade-bar-value');
        setTimeout(() => {
          fill.style.transition = 'width 0.8s ease';
          fill.style.width = `${value * 100}%`;
          this.countUp(valEl, 0, value, 800, 2);
          if (value >= 0.8) fill.style.background = 'var(--accent-green)';
          else if (value >= 0.5) fill.style.background = 'var(--accent-cyan)';
          else fill.style.background = 'var(--accent-amber)';
        }, delay);
        delay += 120;
      });
    }

    // Build penalties/bonuses
    const pbContainer = document.getElementById('final-penalties-bonuses');
    if (pbContainer) {
      pbContainer.innerHTML = '';
      (penalties || []).forEach(p => {
        const el = document.createElement('div');
        el.className = 'penalty-item';
        el.textContent = `❌ ${p.type}: ${p.delta.toFixed(2)} (${p.detail})`;
        pbContainer.appendChild(el);
      });
      (bonuses || []).forEach(b => {
        const el = document.createElement('div');
        el.className = 'bonus-item';
        el.textContent = `✅ ${b.type}: +${b.delta.toFixed(2)} (${b.detail})`;
        pbContainer.appendChild(el);
      });
    }

    // Color the score based on value
    if (scoreEl) {
      setTimeout(() => {
        if (finalScore >= 0.7) scoreEl.style.color = 'var(--accent-green)';
        else if (finalScore >= 0.4) scoreEl.style.color = 'var(--accent-amber)';
        else scoreEl.style.color = 'var(--accent-red)';
        this.scaleBounce(scoreEl, 1.05);
      }, 1600);
    }
  },

  // Red team pivot wow moment
  triggerRedTeamPivot() {
    this.flashScreen('red', 600);
    this.showNotification('⚡ RED TEAM PIVOT DETECTED — Adaptive adversary spreading!', 'red', 4000);
    const rtAlert = document.getElementById('red-team-alert');
    if (rtAlert) {
      rtAlert.classList.remove('hidden');
      setTimeout(() => rtAlert.classList.add('hidden'), 8000);
    }
  },
};
