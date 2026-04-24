/* ============================================================
   CyberSOC Dashboard — Graph Visualizations
   D3.js v7 Threat Graph + Chart.js Radar + Timeline
   ============================================================ */

// ============================================================
// Client-side Threat Graph State
// ============================================================
class ClientThreatGraph {
  constructor() {
    this.nodes = new Map();   // id -> node object
    this.links = [];          // {source, target, edgeType, id}
    this._linkSet = new Set(); // "source|target|type" for dedup
    this._pivotLinks = new Set();
  }

  addNode(node) {
    if (!this.nodes.has(node.id)) {
      this.nodes.set(node.id, { ...node, _new: true });
    }
    return this;
  }

  updateNode(id, updates) {
    if (this.nodes.has(id)) {
      Object.assign(this.nodes.get(id), updates, { _updated: true });
    }
    return this;
  }

  addLink(sourceId, targetId, edgeType) {
    const key = `${sourceId}|${targetId}|${edgeType}`;
    const rkey = `${targetId}|${sourceId}|${edgeType}`;
    if (this._linkSet.has(key) || this._linkSet.has(rkey)) return this;
    this._linkSet.add(key);
    const link = { source: sourceId, target: targetId, edgeType, id: key };
    this.links.push(link);
    if (edgeType === 'pivoted_from') this._pivotLinks.add(key);
    return this;
  }

  hasPivotLinks() { return this._pivotLinks.size > 0; }

  getGraphData() {
    return {
      nodes: [...this.nodes.values()],
      links: [...this.links],
    };
  }

  // Update from a full SOCObservation
  updateFromObservation(obs, lastAction) {
    // Always sync alert nodes and hosts from alert_queue
    (obs.alert_queue || []).forEach(alert => {
      const existing = this.nodes.get(alert.alert_id);
      if (!existing) {
        this.addNode({
          id: alert.alert_id,
          nodeType: 'alert',
          label: alert.alert_id,
          severity: alert.severity,
          sourceHost: alert.source_host,
          threatType: alert.threat_type,
          description: alert.description,
          isPivot: alert.alert_id.startsWith('PIVOT-'),
          subnet: alert.subnet,
        });
      }

      // Add source host
      if (!this.nodes.has(alert.source_host)) {
        this.addNode({
          id: alert.source_host,
          nodeType: 'host',
          label: alert.source_host,
          status: 'online',
          subnet: alert.subnet || this._subnetFromHostname(alert.source_host),
        });
      } else if (!this.nodes.get(alert.source_host).subnet) {
        this.updateNode(alert.source_host, { subnet: alert.subnet || this._subnetFromHostname(alert.source_host) });
      }

      // Link alert to host
      this.addLink(alert.source_host, alert.alert_id, 'involves');

      // Add IOC nodes
      (alert.ioc_indicators || []).forEach(ioc => {
        if (!this.nodes.has(ioc)) {
          this.addNode({
            id: ioc,
            nodeType: 'ioc',
            label: ioc.length > 22 ? ioc.substring(0, 20) + '…' : ioc,
            fullLabel: ioc,
            iocType: this._guessIocType(ioc),
            blocked: false,
            enriched: false,
          });
        }
        this.addLink(alert.alert_id, ioc, 'involves');
      });
    });

    // Process based on last action
    if (!lastAction) return;

    const actionType = lastAction.type;

    if (actionType === 'run_forensics' && obs.host_forensics) {
      const f = obs.host_forensics;
      this.updateNode(f.hostname, {
        status: f.is_compromised ? 'compromised' : 'online',
        forensicsRun: true,
        maliciousProcs: f.malicious_processes,
      });

      (f.malicious_processes || []).forEach(proc => {
        const procId = `${f.hostname}:${proc}`;
        this.addNode({
          id: procId,
          nodeType: 'process',
          label: proc,
          hostname: f.hostname,
          processName: proc,
          killed: false,
        });
        this.addLink(procId, f.hostname, 'runs_on');
      });

      (f.network_connections || []).forEach(conn => {
        const ip = conn.split(':')[0];
        if (!this.nodes.has(ip)) {
          this.addNode({ id: ip, nodeType: 'ioc', label: ip, iocType: 'ip', blocked: false, enriched: false });
        }
        this.addLink(f.hostname, ip, 'communicates_with');
      });
    }

    if (actionType === 'query_host') {
      const hn = lastAction.hostname;
      const subnet = this._subnetFromHostname(hn);
      const existing = this.nodes.get(hn);
      if (existing) {
        this.updateNode(hn, {
          status: existing.status === 'compromised' ? 'compromised' : 'queried',
          subnet: existing.subnet || subnet,
        });
      } else {
        this.addNode({ id: hn, nodeType: 'host', label: hn, status: 'queried', subnet });
      }
    }

    if (actionType === 'enrich_ioc') {
      const iocVal = lastAction.ioc_value;
      if (!this.nodes.has(iocVal)) {
        this.addNode({
          id: iocVal,
          nodeType: 'ioc',
          label: iocVal.length > 22 ? iocVal.substring(0, 20) + '…' : iocVal,
          fullLabel: iocVal,
          iocType: lastAction.ioc_type || this._guessIocType(iocVal),
          blocked: false,
          enriched: false,
        });
      }
      if (obs.ioc_enrichment) {
        this.updateNode(iocVal, {
          enriched: true,
          threatActor: obs.ioc_enrichment.threat_actor,
          mitreTTPs: obs.ioc_enrichment.mitre_ttps || [],
          reputation: obs.ioc_enrichment.reputation,
        });
      }
    }

    if (actionType === 'block_ioc') {
      this.updateNode(lastAction.ioc_value, { blocked: true });
    }

    if (actionType === 'kill_process') {
      const procId = `${lastAction.hostname}:${lastAction.process_name}`;
      this.updateNode(procId, { killed: true });
      // Also add process node if not seen before
      if (!this.nodes.has(procId)) {
        this.addNode({
          id: procId, nodeType: 'process', label: lastAction.process_name,
          hostname: lastAction.hostname, killed: true,
        });
      }
    }

    if (actionType === 'isolate_segment') {
      const subnet = lastAction.subnet;
      this.nodes.forEach((node, id) => {
        if (node.nodeType === 'host' && node.subnet === subnet) {
          this.updateNode(id, { status: 'isolated' });
        }
      });
    }

    if (actionType === 'scan_host_vulnerabilities' && obs.vulnerability_results) {
      (obs.vulnerability_results || []).forEach(vuln => {
        const vid = vuln.cve_id || 'CVE-UNKNOWN';
        this.addNode({
          id: vid, nodeType: 'vulnerability', label: vid,
          cvssScore: vuln.cvss_score, exploitability: vuln.exploitability,
          hostname: lastAction.hostname,
        });
        this.addLink(vid, lastAction.hostname, 'exploits');
      });
    }

    if (actionType === 'correlate_alerts' && obs.correlation_results) {
      const aids = lastAction.alert_ids || [];
      for (let i = 0; i < aids.length - 1; i++) {
        this.addLink(aids[i], aids[i + 1], 'part_of_chain');
      }
      // Mark alerts as correlated
      aids.forEach(id => this.updateNode(id, { correlated: true }));
    }
  }

  _guessIocType(ioc) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ioc)) return 'ip';
    if (/[a-f0-9]{32,64}/i.test(ioc)) return 'hash';
    return 'domain';
  }

  _subnetFromHostname(hostname) {
    if (!hostname) return null;
    const prefix = hostname.split('-')[0].toUpperCase();
    const map = { WS: 'corporate', DEV: 'engineering', FIN: 'finance', DMZ: 'dmz', SRV: 'datacenter', EXEC: 'executive' };
    return map[prefix] || null;
  }

  // Detect new pivot alerts (PIVOT-xxx)
  getNewPivotAlerts(prevAlertIds) {
    const pivots = [];
    this.nodes.forEach((node, id) => {
      if (node.nodeType === 'alert' && node.isPivot && !prevAlertIds.has(id)) {
        pivots.push(node);
      }
    });
    return pivots;
  }
}


// ============================================================
// D3.js Force-Directed Threat Graph Visualization
// ============================================================
class ThreatGraphViz {
  constructor(containerId) {
    this.containerId = containerId;
    this.svg = null;
    this.simulation = null;
    this.graphGroup = null;
    this.linkGroup = null;
    this.nodeGroup = null;
    this.labelGroup = null;
    this.tooltip = null;
    this.width = 0;
    this.height = 0;
    this._pivotTimers = [];
    this._nodeData = [];
    this._linkData = [];
    this._initialized = false;
  }

  init() {
    const container = document.getElementById(this.containerId);
    if (!container) return;
    const svg = d3.select('#threat-graph-svg');
    const rect = container.getBoundingClientRect();
    this.width = rect.width || 600;
    this.height = rect.height || 400;

    svg.attr('width', this.width).attr('height', this.height);

    // Add SVG filters for glow effects
    const defs = svg.append('defs');
    this._addGlowFilters(defs);

    // Background
    svg.append('rect')
      .attr('width', this.width).attr('height', this.height)
      .attr('fill', 'transparent');

    // Zoom behavior
    const zoom = d3.zoom()
      .scaleExtent([0.2, 4])
      .on('zoom', (event) => {
        this.graphGroup.attr('transform', event.transform);
      });
    svg.call(zoom);

    // Main group
    this.graphGroup = svg.append('g').attr('class', 'graph-group');
    this.linkGroup = this.graphGroup.append('g').attr('class', 'links');
    this.nodeGroup = this.graphGroup.append('g').attr('class', 'nodes');
    this.labelGroup = this.graphGroup.append('g').attr('class', 'labels');

    // Tooltip
    this.tooltip = d3.select('#graph-tooltip');

    // Force simulation
    this.simulation = d3.forceSimulation()
      .force('link', d3.forceLink().id(d => d.id).distance(d => {
        if (d.edgeType === 'pivoted_from') return 120;
        if (d.edgeType === 'runs_on') return 50;
        return 80;
      }).strength(0.7))
      .force('charge', d3.forceManyBody().strength(-180).distanceMax(300))
      .force('center', d3.forceCenter(this.width / 2, this.height / 2))
      .force('collision', d3.forceCollide().radius(d => this._nodeRadius(d) + 8))
      .force('x', d3.forceX(this.width / 2).strength(0.04))
      .force('y', d3.forceY(this.height / 2).strength(0.04));

    this._initialized = true;
  }

  _addGlowFilters(defs) {
    const glows = [
      { id: 'glow-red', color: '#ef4444', stdDev: 4 },
      { id: 'glow-blue', color: '#3b82f6', stdDev: 3 },
      { id: 'glow-green', color: '#10b981', stdDev: 3 },
      { id: 'glow-amber', color: '#f59e0b', stdDev: 3 },
      { id: 'glow-purple', color: '#8b5cf6', stdDev: 3 },
      { id: 'glow-cyan', color: '#06b6d4', stdDev: 3 },
    ];
    glows.forEach(g => {
      const filter = defs.append('filter').attr('id', g.id);
      filter.append('feGaussianBlur').attr('in', 'SourceGraphic').attr('stdDeviation', g.stdDev).attr('result', 'blur');
      const merge = filter.append('feMerge');
      merge.append('feMergeNode').attr('in', 'blur');
      merge.append('feMergeNode').attr('in', 'SourceGraphic');
    });

    // Arrowhead markers for directed edges
    const arrows = [
      { id: 'arrow-default',    color: 'rgba(148,163,184,0.6)' },
      { id: 'arrow-pivot',      color: '#ef4444' },
      { id: 'arrow-c2',         color: 'rgba(245,158,11,0.7)' },
      { id: 'arrow-exploit',    color: 'rgba(239,68,68,0.7)' },
      { id: 'arrow-chain',      color: 'rgba(139,92,246,0.7)' },
    ];
    arrows.forEach(a => {
      defs.append('marker')
        .attr('id', a.id)
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 14)
        .attr('refY', 0)
        .attr('markerWidth', 5)
        .attr('markerHeight', 5)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-5L10,0L0,5')
        .attr('fill', a.color);
    });
  }

  _edgeMarker(edgeType) {
    if (edgeType === 'pivoted_from') return 'url(#arrow-pivot)';
    if (edgeType === 'communicates_with') return 'url(#arrow-c2)';
    if (edgeType === 'exploits') return 'url(#arrow-exploit)';
    if (edgeType === 'part_of_chain') return 'url(#arrow-chain)';
    if (edgeType === 'runs_on') return 'url(#arrow-default)';
    return null;
  }

  update(graphData) {
    if (!this._initialized) return;

    const nodes = graphData.nodes;
    const links = graphData.links.map(l => ({
      ...l,
      source: l.source.id || l.source,
      target: l.target.id || l.target,
    }));

    this._nodeData = nodes;
    this._linkData = links;

    // Update links (curved quadratic bezier paths)
    const linkSel = this.linkGroup.selectAll('.graph-link')
      .data(links, d => d.id);

    const linkEnter = linkSel.enter().append('path')
      .attr('class', d => `graph-link ${d.edgeType}`)
      .attr('fill', 'none')
      .attr('marker-end', d => this._edgeMarker(d.edgeType))
      .attr('stroke-opacity', 0)
      .transition().duration(600)
      .attr('stroke-opacity', d => d.edgeType === 'pivoted_from' ? 0.9 : 0.6);

    linkSel
      .attr('class', d => `graph-link ${d.edgeType}`)
      .attr('marker-end', d => this._edgeMarker(d.edgeType));
    linkSel.exit().transition().duration(300).attr('stroke-opacity', 0).remove();

    // Update nodes
    const nodeSel = this.nodeGroup.selectAll('.graph-node')
      .data(nodes, d => d.id);

    const nodeEnter = nodeSel.enter().append('path')
      .attr('class', 'graph-node')
      .attr('d', d => this._nodeSymbol(d))
      .attr('transform', d => `translate(${this.width / 2},${this.height / 2}) scale(0)`)
      .attr('fill', d => this._nodeColor(d))
      .attr('stroke', d => this._nodeStroke(d))
      .attr('stroke-width', d => d.nodeType === 'host' ? 2 : 1.5)
      .attr('filter', d => this._nodeFilter(d))
      .attr('cursor', 'pointer')
      .on('mouseover', (event, d) => this._showTooltip(event, d))
      .on('mouseout', () => this._hideTooltip())
      .on('click', (event, d) => this._highlightNode(d));

    nodeEnter.transition().duration(500).ease(d3.easeBounceOut)
      .attr('transform', d => `translate(${d.x || this.width/2},${d.y || this.height/2}) scale(1)`);

    nodeSel.transition().duration(300)
      .attr('fill', d => this._nodeColor(d))
      .attr('stroke', d => this._nodeStroke(d))
      .attr('filter', d => this._nodeFilter(d));

    nodeSel.exit().transition().duration(300)
      .attr('transform', d => `translate(${d.x},${d.y}) scale(0)`)
      .remove();

    // Update labels
    const labelSel = this.labelGroup.selectAll('.node-label')
      .data(nodes.filter(d => d.nodeType === 'host' || d.nodeType === 'vulnerability'), d => d.id);

    const labelEnter = labelSel.enter().append('text')
      .attr('class', 'node-label')
      .attr('text-anchor', 'middle')
      .attr('dy', d => this._nodeRadius(d) + 12)
      .attr('opacity', 0)
      .text(d => d.label);

    labelEnter.transition().duration(500).attr('opacity', 0.7);
    labelSel.text(d => d.label);
    labelSel.exit().remove();

    // Drag behavior
    const drag = d3.drag()
      .on('start', (event, d) => {
        if (!event.active) this.simulation.alphaTarget(0.3).restart();
        d.fx = d.x; d.fy = d.y;
      })
      .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
      .on('end', (event, d) => {
        if (!event.active) this.simulation.alphaTarget(0);
        d.fx = null; d.fy = null;
      });

    this.nodeGroup.selectAll('.graph-node').call(drag);

    // Restart simulation
    this.simulation.nodes(nodes).on('tick', () => this._tick());
    this.simulation.force('link').links(links);
    this.simulation.alpha(0.5).restart();
  }

  _tick() {
    this.linkGroup.selectAll('.graph-link')
      .attr('d', d => {
        const sx = d.source.x || 0, sy = d.source.y || 0;
        const tx = d.target.x || 0, ty = d.target.y || 0;
        const dx = tx - sx, dy = ty - sy;
        const len = Math.sqrt(dx * dx + dy * dy) || 1;
        // Perpendicular offset — bigger curve for pivot edges
        const offset = d.edgeType === 'pivoted_from' ? 50 : (d.edgeType === 'part_of_chain' ? 8 : 20);
        const cx = (sx + tx) / 2 - (dy / len) * offset;
        const cy = (sy + ty) / 2 + (dx / len) * offset;
        return `M${sx},${sy} Q${cx},${cy} ${tx},${ty}`;
      });

    this.nodeGroup.selectAll('.graph-node')
      .attr('transform', d => `translate(${d.x || 0},${d.y || 0})`);

    this.labelGroup.selectAll('.node-label')
      .attr('x', d => d.x || 0)
      .attr('y', d => d.y || 0);
  }

  _nodeRadius(d) {
    if (d.nodeType === 'host') return 12;
    if (d.nodeType === 'process') return 7;
    if (d.nodeType === 'alert') return 9;
    if (d.nodeType === 'vulnerability') return 8;
    return 8; // ioc
  }

  _nodeSymbol(d) {
    const size = this._nodeRadius(d) * this._nodeRadius(d) * Math.PI;
    if (d.nodeType === 'host') return d3.symbol().type(d3.symbolCircle).size(size * 1.2)();
    if (d.nodeType === 'process') return d3.symbol().type(d3.symbolDiamond).size(size)();
    if (d.nodeType === 'alert') return d3.symbol().type(d3.symbolTriangle).size(size)();
    if (d.nodeType === 'vulnerability') return d3.symbol().type(d3.symbolSquare).size(size)();
    // IOC = hexagon-like using wye
    return d3.symbol().type(d3.symbolWye).size(size)();
  }

  _nodeColor(d) {
    if (d.nodeType === 'host') {
      if (d.status === 'compromised') return '#ef4444';
      if (d.status === 'isolated') return '#6b7280';
      if (d.status === 'queried') return '#06b6d4';
      return '#3b82f6';
    }
    if (d.nodeType === 'process') {
      return d.killed ? '#6b7280' : '#f59e0b';
    }
    if (d.nodeType === 'ioc') {
      if (d.blocked) return 'transparent';
      if (d.enriched) return '#8b5cf6';
      return '#ef4444';
    }
    if (d.nodeType === 'alert') {
      const colors = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#10b981' };
      return d.isPivot ? '#ef4444' : (colors[d.severity] || '#94a3b8');
    }
    if (d.nodeType === 'vulnerability') return 'transparent';
    return '#94a3b8';
  }

  _nodeStroke(d) {
    if (d.nodeType === 'ioc') {
      if (d.blocked) return '#10b981';
      if (d.enriched) return '#8b5cf6';
      return '#ef4444';
    }
    if (d.nodeType === 'vulnerability') return '#10b981';
    if (d.nodeType === 'host' && d.status === 'compromised') return '#fca5a5';
    if (d.nodeType === 'host' && d.status === 'isolated') return '#f59e0b';
    return 'transparent';
  }

  _nodeFilter(d) {
    if (d.nodeType === 'host' && d.status === 'compromised') return 'url(#glow-red)';
    if (d.nodeType === 'host' && d.status === 'queried') return 'url(#glow-cyan)';
    if (d.nodeType === 'ioc' && d.enriched) return 'url(#glow-purple)';
    if (d.nodeType === 'ioc' && d.blocked) return 'url(#glow-green)';
    if (d.nodeType === 'alert' && d.isPivot) return 'url(#glow-red)';
    if (d.nodeType === 'alert' && d.severity === 'critical') return 'url(#glow-amber)';
    if (d.nodeType === 'process' && !d.killed) return 'url(#glow-amber)';
    return null;
  }

  _showTooltip(event, d) {
    const tt = this.tooltip;
    if (!tt) return;
    let html = `<div class="graph-tooltip-title">${d.label || d.id}</div>`;
    html += `<div class="graph-tooltip-row"><span class="graph-tooltip-key">Type:</span><span class="graph-tooltip-value">${d.nodeType}</span></div>`;

    if (d.nodeType === 'host') {
      html += `<div class="graph-tooltip-row"><span class="graph-tooltip-key">Status:</span><span class="graph-tooltip-value">${d.status || 'online'}</span></div>`;
      html += `<div class="graph-tooltip-row"><span class="graph-tooltip-key">Subnet:</span><span class="graph-tooltip-value">${d.subnet || '—'}</span></div>`;
    } else if (d.nodeType === 'ioc') {
      html += `<div class="graph-tooltip-row"><span class="graph-tooltip-key">IOC Type:</span><span class="graph-tooltip-value">${d.iocType || '—'}</span></div>`;
      html += `<div class="graph-tooltip-row"><span class="graph-tooltip-key">Blocked:</span><span class="graph-tooltip-value">${d.blocked ? '✅' : '❌'}</span></div>`;
      html += `<div class="graph-tooltip-row"><span class="graph-tooltip-key">Enriched:</span><span class="graph-tooltip-value">${d.enriched ? '✅' : '❌'}</span></div>`;
      if (d.threatActor) html += `<div class="graph-tooltip-row"><span class="graph-tooltip-key">Actor:</span><span class="graph-tooltip-value">${d.threatActor}</span></div>`;
    } else if (d.nodeType === 'process') {
      html += `<div class="graph-tooltip-row"><span class="graph-tooltip-key">Host:</span><span class="graph-tooltip-value">${d.hostname || '—'}</span></div>`;
      html += `<div class="graph-tooltip-row"><span class="graph-tooltip-key">Status:</span><span class="graph-tooltip-value">${d.killed ? '💀 Killed' : '⚠️ Running'}</span></div>`;
    } else if (d.nodeType === 'alert') {
      html += `<div class="graph-tooltip-row"><span class="graph-tooltip-key">Severity:</span><span class="graph-tooltip-value">${d.severity}</span></div>`;
      html += `<div class="graph-tooltip-row"><span class="graph-tooltip-key">Host:</span><span class="graph-tooltip-value">${d.sourceHost || '—'}</span></div>`;
      if (d.isPivot) html += `<div style="color:#ef4444;margin-top:4px;font-size:10px;">⚡ LATERAL PIVOT</div>`;
    } else if (d.nodeType === 'vulnerability') {
      html += `<div class="graph-tooltip-row"><span class="graph-tooltip-key">CVSS:</span><span class="graph-tooltip-value">${d.cvssScore}</span></div>`;
      html += `<div class="graph-tooltip-row"><span class="graph-tooltip-key">Exploitability:</span><span class="graph-tooltip-value">${d.exploitability}</span></div>`;
    }

    tt.classed('hidden', false)
      .style('left', (event.offsetX + 12) + 'px')
      .style('top', (event.offsetY - 10) + 'px')
      .html(html);
  }

  _hideTooltip() {
    if (this.tooltip) this.tooltip.classed('hidden', true);
  }

  _highlightNode(d) {
    // Dim all, highlight connected nodes
    const connectedIds = new Set([d.id]);
    this._linkData.forEach(l => {
      const src = l.source.id || l.source;
      const tgt = l.target.id || l.target;
      if (src === d.id || tgt === d.id) {
        connectedIds.add(src); connectedIds.add(tgt);
      }
    });

    this.nodeGroup.selectAll('.graph-node')
      .attr('opacity', n => connectedIds.has(n.id) ? 1 : 0.2);
    this.linkGroup.selectAll('.graph-link')
      .attr('opacity', l => {
        const src = l.source.id || l.source;
        const tgt = l.target.id || l.target;
        return (src === d.id || tgt === d.id) ? 1 : 0.1;
      });

    // Reset after 3s
    setTimeout(() => {
      this.nodeGroup.selectAll('.graph-node').attr('opacity', 1);
      this.linkGroup.selectAll('.graph-link').attr('opacity', l =>
        l.edgeType === 'pivoted_from' ? 0.9 : 0.6
      );
    }, 3000);
  }

  // Animate a pivot edge with traveling dot
  animatePivot(sourceId, targetId) {
    const pivotLink = this._linkData.find(l => {
      const s = l.source.id || l.source;
      const t = l.target.id || l.target;
      return l.edgeType === 'pivoted_from' && ((s === sourceId && t === targetId) || (s === targetId && t === sourceId));
    });
    if (!pivotLink) return;

    const dot = this.graphGroup.append('circle')
      .attr('r', 5)
      .attr('fill', '#ef4444')
      .attr('filter', 'url(#glow-red)')
      .attr('opacity', 0);

    let elapsed = 0;
    const duration = 1500;
    const cycles = 5;
    const total = duration * cycles;

    const timer = d3.timer(t => {
      elapsed = t;
      const progress = (t % duration) / duration;
      const src = pivotLink.source;
      const tgt = pivotLink.target;
      if (!src || !tgt) { timer.stop(); dot.remove(); return; }
      const sx = src.x || 0, sy = src.y || 0;
      const tx = tgt.x || 0, ty = tgt.y || 0;
      const x = sx + (tx - sx) * progress;
      const y = sy + (ty - sy) * progress;
      dot.attr('cx', x).attr('cy', y).attr('opacity', Math.sin(progress * Math.PI) * 0.9 + 0.1);
      if (t > total) { timer.stop(); dot.remove(); }
    });

    this._pivotTimers.push(timer);
  }

  // Flash a specific node
  flashNode(nodeId, color = 'red') {
    const filterMap = { red: 'glow-red', blue: 'glow-blue', green: 'glow-green' };
    const filter = `url(#${filterMap[color] || 'glow-red'})`;
    const node = this.nodeGroup.selectAll('.graph-node').filter(d => d.id === nodeId);
    if (node.empty()) return;
    node.transition().duration(200).attr('filter', filter)
      .transition().duration(200).attr('filter', null)
      .transition().duration(200).attr('filter', filter)
      .transition().duration(200).attr('filter', null)
      .transition().duration(200).attr('filter', filter)
      .transition().duration(500).attr('filter', d => this._nodeFilter(d));
  }
}


// ============================================================
// Chart.js — 10-Dimensional Score Radar
// ============================================================
class RadarChart {
  constructor(canvasId) {
    this.canvasId = canvasId;
    this.chart = null;
    this.scores = {
      threat_containment: 0, ioc_blocking: 0, forensic_investigation: 0,
      siem_correlation: 0, threat_intel_usage: 0, vuln_root_cause: 0,
      business_impact: 0, step_efficiency: 0, plan_coverage: 0, plan_evidence_quality: 0,
    };
  }

  init() {
    const canvas = document.getElementById(this.canvasId);
    if (!canvas || !window.Chart) return;
    const ctx = canvas.getContext('2d');

    this.chart = new Chart(ctx, {
      type: 'radar',
      data: {
        labels: [
          'Threat\nContainment',
          'IOC\nBlocking',
          'Forensic\nInvest.',
          'SIEM\nCorrelation',
          'Threat\nIntel',
          'Vuln\nRoot Cause',
          'Business\nImpact',
          'Step\nEfficiency',
          'Plan\nCoverage',
          'Plan\nEvidence',
        ],
        datasets: [{
          data: Object.values(this.scores),
          backgroundColor: 'rgba(6,182,212,0.15)',
          borderColor: '#06b6d4',
          borderWidth: 2,
          pointBackgroundColor: '#3b82f6',
          pointBorderColor: '#06b6d4',
          pointBorderWidth: 1,
          pointRadius: 3,
          pointHoverRadius: 5,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 600, easing: 'easeInOutQuart' },
        scales: {
          r: {
            beginAtZero: true,
            min: 0,
            max: 1,
            ticks: {
              count: 5,
              color: '#4b5563',
              font: { family: 'JetBrains Mono', size: 9 },
              backdropColor: 'transparent',
              stepSize: 0.25,
            },
            grid: { color: 'rgba(42,48,64,0.8)', circular: false },
            angleLines: { color: 'rgba(42,48,64,0.6)' },
            pointLabels: {
              color: '#94a3b8',
              font: { family: 'Inter', size: 9, weight: '500' },
            },
          },
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#1a1f2e',
            borderColor: '#2a3040',
            borderWidth: 1,
            titleColor: '#06b6d4',
            bodyColor: '#94a3b8',
            titleFont: { family: 'JetBrains Mono', size: 11 },
            bodyFont: { family: 'JetBrains Mono', size: 10 },
            callbacks: {
              label: (ctx) => ` ${ctx.raw.toFixed(3)}`,
            },
          },
        },
      },
    });
  }

  update(breakdown) {
    if (!this.chart || !breakdown) return;
    const order = [
      'threat_containment', 'ioc_blocking', 'forensic_investigation',
      'siem_correlation', 'threat_intel_usage', 'vuln_root_cause',
      'business_impact', 'step_efficiency', 'plan_coverage', 'plan_evidence_quality',
    ];
    this.chart.data.datasets[0].data = order.map(k => breakdown[k] ?? 0);
    this.chart.update('active');
  }

  // Incrementally update a single dimension (for live updates during episode)
  updateDimension(key, value) {
    const order = [
      'threat_containment', 'ioc_blocking', 'forensic_investigation',
      'siem_correlation', 'threat_intel_usage', 'vuln_root_cause',
      'business_impact', 'step_efficiency', 'plan_coverage', 'plan_evidence_quality',
    ];
    const idx = order.indexOf(key);
    if (idx < 0 || !this.chart) return;
    this.chart.data.datasets[0].data[idx] = value;
    this.chart.update('none');
  }
}


// ============================================================
// Chart.js — Cumulative Reward Timeline
// ============================================================
class RewardTimeline {
  constructor(canvasId) {
    this.canvasId = canvasId;
    this.chart = null;
  }

  init() {
    const canvas = document.getElementById(this.canvasId);
    if (!canvas || !window.Chart) return;
    const ctx = canvas.getContext('2d');

    // Gradient fill
    const gradient = ctx.createLinearGradient(0, 0, 0, 100);
    gradient.addColorStop(0, 'rgba(16,185,129,0.3)');
    gradient.addColorStop(1, 'rgba(16,185,129,0.02)');

    this.chart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: [],
        datasets: [{
          data: [],
          borderColor: '#10b981',
          backgroundColor: gradient,
          borderWidth: 2,
          pointRadius: 3,
          pointBackgroundColor: ctx => {
            const v = ctx.raw;
            return v < 0 ? '#ef4444' : '#10b981';
          },
          pointBorderColor: 'transparent',
          tension: 0.3,
          fill: true,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 300 },
        scales: {
          x: {
            grid: { color: 'rgba(42,48,64,0.5)' },
            ticks: { color: '#4b5563', font: { family: 'JetBrains Mono', size: 9 }, maxTicksLimit: 10 },
            title: { display: true, text: 'Step', color: '#4b5563', font: { size: 9 } },
          },
          y: {
            grid: { color: 'rgba(42,48,64,0.5)' },
            ticks: { color: '#4b5563', font: { family: 'JetBrains Mono', size: 9 } },
            title: { display: true, text: 'Reward', color: '#4b5563', font: { size: 9 } },
          },
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#1a1f2e',
            borderColor: '#2a3040',
            borderWidth: 1,
            titleColor: '#06b6d4',
            bodyColor: '#94a3b8',
            titleFont: { family: 'JetBrains Mono', size: 10 },
            bodyFont: { family: 'JetBrains Mono', size: 10 },
          },
          annotation: {
            annotations: {
              zeroLine: {
                type: 'line',
                yMin: 0, yMax: 0,
                borderColor: 'rgba(148,163,184,0.3)',
                borderWidth: 1,
                borderDash: [4, 4],
              },
            },
          },
        },
      },
    });
  }

  addPoint(step, cumulativeReward, actionType) {
    if (!this.chart) return;
    this.chart.data.labels.push(`${step}`);
    this.chart.data.datasets[0].data.push(parseFloat(cumulativeReward.toFixed(3)));
    // Color negative points red
    const colors = this.chart.data.datasets[0].data.map(v => v < 0 ? '#ef4444' : '#10b981');
    this.chart.data.datasets[0].pointBackgroundColor = colors;
    this.chart.update('none');
  }

  reset() {
    if (!this.chart) return;
    this.chart.data.labels = [];
    this.chart.data.datasets[0].data = [];
    this.chart.update('none');
  }
}
