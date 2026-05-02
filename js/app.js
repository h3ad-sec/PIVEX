// PIVEX — app.js
// All logic global (no modules). Loaded after graph-data.js.

// ── State ───────────────────────────────────────────────────────────────────
var cy = null;
var activeArtifact = null;
var activeMode = 'reactive';
var graphMode = 'simple';
var _flowTimer = null;
var _flowOffset = 0;

// ── Category colors ─────────────────────────────────────────────────────────
var CAT_COLORS = {
  network:  { bg: '#00d4ff', border: '#0099bb', text: '#06080f', glow: '#00d4ff' },
  endpoint: { bg: '#00ff9f', border: '#00cc7a', text: '#06080f', glow: '#00ff9f' },
  identity: { bg: '#c084fc', border: '#9333ea', text: '#06080f', glow: '#c084fc' },
  cloud:    { bg: '#60a5fa', border: '#2563eb', text: '#06080f', glow: '#60a5fa' },
  threat:   { bg: '#f87171', border: '#dc2626', text: '#06080f', glow: '#f87171' }
};

// ── Artifact order (for circular layout) ────────────────────────────────────
var ARTIFACT_ORDER = [
  'ip','domain','url','certificate',
  'hash','process','filepath','service','registry','task','mutex','named-pipe','wmi','netshare','host',
  'user','email','credential',
  'cloud',
  'vuln'
];

// ── applyCircularLayout ──────────────────────────────────────────────────────
function applyCircularLayout() {
  if (!cy) return;
  var artNodes = cy.nodes('[type = "artifact"]');
  var n = artNodes.length;
  if (!n) return;
  var container = document.getElementById('cy');
  var w = container ? container.offsetWidth  : 800;
  var h = container ? container.offsetHeight : 560;
  var cx = w / 2;
  var cyCenter = h / 2;
  var radius = Math.min(w, h) * 0.38;

  // Map id → ordered index
  var orderMap = {};
  ARTIFACT_ORDER.forEach(function(id, i) { orderMap[id] = i; });

  artNodes.forEach(function(node) {
    var id = node.id();
    var idx = (orderMap[id] !== undefined) ? orderMap[id] : 0;
    var angle = (idx / ARTIFACT_ORDER.length) * 2 * Math.PI - Math.PI / 2;
    node.position({ x: cx + radius * Math.cos(angle), y: cyCenter + radius * Math.sin(angle) });
  });

  cy.fit(artNodes, 50);
}

// ── startEdgeFlow / stopEdgeFlow ─────────────────────────────────────────────
function startEdgeFlow() {
  stopEdgeFlow();
  _flowOffset = 0;
  _flowTimer = setInterval(function() {
    _flowOffset = (_flowOffset + 1) % 30;
    if (cy) {
      cy.edges('.highlighted').style('line-dash-offset', -_flowOffset);
    }
  }, 50);
}

function stopEdgeFlow() {
  if (_flowTimer) { clearInterval(_flowTimer); _flowTimer = null; }
  if (cy) cy.edges().style('line-dash-offset', 0);
}

// ── updateStats ──────────────────────────────────────────────────────────────
function updateStats(selectedType) {
  var el = document.getElementById('graph-stats');
  if (!el) return;
  if (!selectedType) {
    var totalNodes = cy ? cy.nodes('[type = "artifact"]').length : 0;
    var totalEdges = cy ? cy.edges('[?crossPivot]').length : 0;
    el.innerHTML = '<span>' + totalNodes + ' artifacts</span><span>' + totalEdges + ' cross-pivots</span>';
    return;
  }
  var pathData = ARTIFACT_PATHS[selectedType];
  var nodeCount = pathData ? pathData.nodes.length : 0;
  el.innerHTML = '<span>' + selectedType.toUpperCase() + ' path</span><span>' + nodeCount + ' nodes</span>';
}

// ── initGraph ───────────────────────────────────────────────────────────────
function initGraph() {
  var container = document.getElementById('cy');
  if (!container) return;

  cy = cytoscape({
    container: container,
    elements: GRAPH_NODES.concat(GRAPH_EDGES),
    style: [
      // ── Base node ──────────────────────────────────────────────────────
      { selector: 'node', style: {
          'shape': 'roundrectangle',
          'label': 'data(label)',
          'font-family': 'Share Tech Mono, monospace',
          'font-size': '10px',
          'padding': '8px',
          'width': 'label',
          'height': 'label',
          'text-valign': 'center',
          'text-halign': 'center',
          'text-wrap': 'wrap',
          'text-max-width': '90px',
          'background-color': '#1e3050',
          'border-color': '#3a5470',
          'border-width': 1.5,
          'color': '#e2eeff'
      }},
      // ── Artifact nodes by category ─────────────────────────────────────
      { selector: 'node[type = "artifact"][category = "network"]',
        style: { 'background-color': '#00d4ff', 'border-color': '#0099bb', 'color': '#06080f', 'border-width': 2, 'font-size': '11px', 'font-weight': 'bold' }},
      { selector: 'node[type = "artifact"][category = "endpoint"]',
        style: { 'background-color': '#00ff9f', 'border-color': '#00cc7a', 'color': '#06080f', 'border-width': 2, 'font-size': '11px', 'font-weight': 'bold' }},
      { selector: 'node[type = "artifact"][category = "identity"]',
        style: { 'background-color': '#c084fc', 'border-color': '#9333ea', 'color': '#06080f', 'border-width': 2, 'font-size': '11px', 'font-weight': 'bold' }},
      { selector: 'node[type = "artifact"][category = "cloud"]',
        style: { 'background-color': '#60a5fa', 'border-color': '#2563eb', 'color': '#06080f', 'border-width': 2, 'font-size': '11px', 'font-weight': 'bold' }},
      { selector: 'node[type = "artifact"][category = "threat"]',
        style: { 'background-color': '#f87171', 'border-color': '#dc2626', 'color': '#06080f', 'border-width': 2, 'font-size': '11px', 'font-weight': 'bold' }},
      // ── Non-artifact node types ────────────────────────────────────────
      { selector: 'node[type = "enrichment"]',  style: { 'background-color': '#3b82f6', 'border-color': '#2563eb', 'color': '#ffffff' }},
      { selector: 'node[type = "context"]',     style: { 'background-color': '#a855f7', 'border-color': '#9333ea', 'color': '#ffffff' }},
      { selector: 'node[type = "pivot"]',       style: { 'background-color': '#ffd60a', 'border-color': '#c9a800', 'color': '#06080f' }},
      { selector: 'node[type = "correlation"]', style: { 'background-color': '#f97316', 'border-color': '#c95d0a', 'color': '#ffffff' }},
      { selector: 'node[type = "action"]',      style: { 'background-color': '#ec4899', 'border-color': '#c4186e', 'color': '#ffffff' }},
      { selector: '#dec-malicious',  style: { 'background-color': '#ff3b5c', 'border-color': '#cc2244', 'color': '#ffffff' }},
      { selector: '#dec-suspicious', style: { 'background-color': '#ffd60a', 'border-color': '#c9a800', 'color': '#06080f' }},
      { selector: '#dec-benign',     style: { 'background-color': '#00ff9f', 'border-color': '#00cc7a', 'color': '#06080f' }},
      { selector: '#dec-unknown',    style: { 'background-color': '#7d8fb3', 'border-color': '#5a6e92', 'color': '#ffffff' }},
      // ── Edges ──────────────────────────────────────────────────────────
      { selector: 'edge', style: {
          'width': 1, 'opacity': 0.4,
          'line-color': '#3a5470', 'target-arrow-color': '#3a5470',
          'target-arrow-shape': 'triangle', 'curve-style': 'bezier'
      }},
      { selector: 'edge[?crossPivot]', style: {
          'width': 2, 'line-style': 'dashed',
          'line-dash-pattern': [6, 3], 'line-dash-offset': 0,
          'opacity': 0.75,
          'line-color': '#00ff9f', 'target-arrow-color': '#00ff9f'
      }},
      // ── Highlight / dim / selected states ─────────────────────────────
      { selector: 'node.highlighted', style: {
          'opacity': 1, 'border-width': 3,
          'shadow-blur': 18, 'shadow-opacity': 0.65, 'z-index': 10
      }},
      { selector: 'node[category = "network"].highlighted',  style: { 'border-color': '#00d4ff', 'shadow-color': '#00d4ff' }},
      { selector: 'node[category = "endpoint"].highlighted', style: { 'border-color': '#00ff9f', 'shadow-color': '#00ff9f' }},
      { selector: 'node[category = "identity"].highlighted', style: { 'border-color': '#c084fc', 'shadow-color': '#c084fc' }},
      { selector: 'node[category = "cloud"].highlighted',    style: { 'border-color': '#60a5fa', 'shadow-color': '#60a5fa' }},
      { selector: 'node[category = "threat"].highlighted',   style: { 'border-color': '#f87171', 'shadow-color': '#f87171' }},
      { selector: 'node[type != "artifact"].highlighted',    style: { 'border-color': '#ffd60a', 'shadow-color': '#ffd60a' }},
      { selector: 'edge.highlighted', style: {
          'opacity': 1, 'width': 2.5,
          'line-color': '#ffd60a', 'target-arrow-color': '#ffd60a',
          'line-style': 'dashed', 'line-dash-pattern': [6, 3]
      }},
      { selector: 'node.dimmed', style: { 'opacity': 0.07 }},
      { selector: 'edge.dimmed', style: { 'opacity': 0.04 }},
      { selector: 'node.selected', style: { 'border-color': '#ffd60a', 'border-width': 3.5 }},
      // ── Simple mode hides non-artifact elements ────────────────────────
      { selector: 'node[type != "artifact"]', style: { 'display': 'none' }},
      { selector: 'edge[!crossPivot]',        style: { 'display': 'none' }},
      { selector: 'node.view-full',           style: { 'display': 'element' }},
      { selector: 'edge.view-full',           style: { 'display': 'element' }}
    ],
    layout: { name: 'null' }
  });

  applyCircularLayout();
  updateStats(null);

  cy.on('tap', 'node', function(evt) { showNodeInfo(evt.target); });
  cy.on('tap', function(evt) { if (evt.target === cy) clearNodeInfo(); });
}

// ── selectArtifact ──────────────────────────────────────────────────────────
function selectArtifact(type) {
  stopEdgeFlow();

  if (activeArtifact === type) {
    resetHighlight();
    activeArtifact = null;
    document.querySelectorAll('.artifact-chip').forEach(function(b) {
      b.classList.remove('active');
    });
    var allChip = document.querySelector('.artifact-chip[data-type="all"]');
    if (allChip) allChip.classList.add('active');
    updateStats(null);
    return;
  }

  activeArtifact = type;

  document.querySelectorAll('.artifact-chip').forEach(function(b) {
    b.classList.remove('active');
  });
  var chip = document.querySelector('.artifact-chip[data-type="' + type + '"]');
  if (chip) chip.classList.add('active');

  if (!cy) return;
  updateStats(type);

  if (graphMode === 'simple') {
    var artNode = cy.getElementById(type);
    var connEdges = artNode.connectedEdges('[?crossPivot]');
    var connNodes = connEdges.connectedNodes();
    cy.batch(function() {
      cy.nodes('[type = "artifact"]').forEach(function(n) {
        n.removeClass('highlighted dimmed selected');
        n.addClass(n.id() === type || connNodes.has(n) ? 'highlighted' : 'dimmed');
      });
      cy.edges('[?crossPivot]').forEach(function(e) {
        e.removeClass('highlighted dimmed');
        e.addClass(connEdges.has(e) ? 'highlighted' : 'dimmed');
      });
    });
    startEdgeFlow();
  } else {
    var pathData = ARTIFACT_PATHS[type];
    if (!pathData) return;
    var pathNodeIds = pathData.nodes;
    cy.batch(function() {
      cy.nodes().forEach(function(n) {
        n.removeClass('highlighted dimmed selected');
        n.addClass(pathNodeIds.indexOf(n.data('id')) !== -1 ? 'highlighted' : 'dimmed');
      });
      cy.edges().forEach(function(e) {
        e.removeClass('highlighted dimmed');
        var src = e.data('source'), tgt = e.data('target');
        e.addClass(pathNodeIds.indexOf(src) !== -1 && pathNodeIds.indexOf(tgt) !== -1 ? 'highlighted' : 'dimmed');
      });
    });
    startEdgeFlow();
  }

  showArtifactInfo(type);
}

// ── selectAll ───────────────────────────────────────────────────────────────
function selectAll() {
  stopEdgeFlow();
  resetHighlight();
  activeArtifact = null;
  document.querySelectorAll('.artifact-chip').forEach(function(b) {
    b.classList.remove('active');
  });
  var allChip = document.querySelector('.artifact-chip[data-type="all"]');
  if (allChip) allChip.classList.add('active');
  updateStats(null);

  var panel = document.getElementById('info-panel');
  if (panel) {
    panel.classList.remove('visible');
    panel.innerHTML = '<div class="info-placeholder"><div class="info-ph-icon">&#9672;</div><div class="info-ph-text">Select an artifact type or click any node to see investigation details.</div></div>';
  }
}

// ── resetHighlight ──────────────────────────────────────────────────────────
function resetHighlight() {
  if (!cy) return;
  cy.batch(function() {
    cy.nodes().removeClass('highlighted dimmed selected');
    cy.edges().removeClass('highlighted dimmed');
  });
}

// ── setGraphView ─────────────────────────────────────────────────────────────
function setGraphView(mode) {
  graphMode = mode;
  stopEdgeFlow();
  document.querySelectorAll('.view-btn').forEach(function(b) { b.classList.remove('active'); });
  var btn = document.getElementById('btn-' + mode);
  if (btn) btn.classList.add('active');
  if (!cy) return;
  resetHighlight();
  activeArtifact = null;
  document.querySelectorAll('.artifact-chip').forEach(function(b) { b.classList.remove('active'); });
  var allChip = document.querySelector('.artifact-chip[data-type="all"]');
  if (allChip) allChip.classList.add('active');
  clearNodeInfo();
  updateStats(null);

  cy.batch(function() {
    if (mode === 'full') {
      cy.nodes('[type != "artifact"]').addClass('view-full');
      cy.edges('[!crossPivot]').addClass('view-full');
    } else {
      cy.elements().removeClass('view-full');
    }
  });

  if (mode === 'simple') {
    applyCircularLayout();
  } else {
    cy.elements().layout({
      name: 'cose',
      animate: false, fit: true, padding: 50,
      randomize: false,
      nodeRepulsion: 2048,
      idealEdgeLength: 80,
      edgeElasticity: 0.45,
      gravity: 0.25
    }).run();
  }
}

// ── showNodeInfo ─────────────────────────────────────────────────────────────
function showNodeInfo(node) {
  if (!node) return;
  cy.nodes().removeClass('selected');
  node.addClass('selected');

  var d = node.data();
  var typeLabel = d.type ? d.type.charAt(0).toUpperCase() + d.type.slice(1) : '';

  var pivotsHtml = '';
  if (d.pivots && d.pivots.length) {
    pivotsHtml = '<div class="info-section"><div class="info-section-label">PIVOT TO</div><ul class="info-list">' +
      d.pivots.map(function(p) { return '<li>' + escHtml(p) + '</li>'; }).join('') +
      '</ul></div>';
  }

  var sourcesHtml = '';
  if (d.sources) {
    sourcesHtml = '<div class="info-section"><div class="info-section-label">DATA SOURCES</div><div class="info-sources">' + escHtml(d.sources) + '</div></div>';
  }

  var catBadge = '';
  if (d.category && CAT_COLORS[d.category]) {
    catBadge = '<span class="info-cat-badge" style="background:' + CAT_COLORS[d.category].bg + ';color:' + CAT_COLORS[d.category].text + '">' + d.category + '</span>';
  }

  var html = '<div class="info-header">' +
    '<span class="info-type-badge info-type-' + escHtml(d.type || '') + '">' + escHtml(typeLabel) + '</span>' +
    catBadge +
    '<button class="info-close" onclick="clearNodeInfo()">&#x2715;</button>' +
    '</div>' +
    '<div class="info-title">' + escHtml(d.label || d.id) + '</div>';

  if (d.desc) html += '<div class="info-desc">' + escHtml(d.desc) + '</div>';
  html += sourcesHtml + pivotsHtml;

  var panel = document.getElementById('info-panel');
  if (panel) {
    panel.innerHTML = html;
    panel.classList.add('visible');
  }
}

// ── showArtifactInfo ─────────────────────────────────────────────────────────
function showArtifactInfo(type) {
  var p = ARTIFACT_PATHS[type];
  if (!p) return;

  var catColor = '';
  var nodeData = GRAPH_NODES.find(function(n) { return n.data && n.data.id === type; });
  if (nodeData && nodeData.data.category && CAT_COLORS[nodeData.data.category]) {
    catColor = CAT_COLORS[nodeData.data.category].bg;
  }

  var html = '<div class="info-header">' +
    '<span class="info-type-badge info-type-artifact">Artifact Path</span>' +
    (catColor ? '<span class="info-cat-badge" style="background:' + catColor + ';color:#06080f">' + (nodeData.data.category) + '</span>' : '') +
    '<button class="info-close" onclick="clearNodeInfo()">&#x2715;</button>' +
    '</div>' +
    '<div class="info-title">' + escHtml(p.label) + ' Investigation</div>' +
    '<div class="info-section">' +
      '<div class="info-section-label">PATH COVERAGE</div>' +
      '<div class="info-stat">' + p.nodes.length + ' nodes highlighted</div>' +
    '</div>' +
    '<div class="info-section">' +
      '<div class="info-section-label">MITRE ATT&amp;CK</div>' +
      '<div class="info-mitre">' + escHtml(p.mitre) + '</div>' +
    '</div>' +
    '<div class="info-section">' +
      '<div class="info-section-label">KEY SOURCES</div>' +
      '<div class="info-sources">' + escHtml(p.sources) + '</div>' +
    '</div>' +
    '<div class="info-hint">Click any highlighted node for details.</div>';

  var panel = document.getElementById('info-panel');
  if (panel) {
    panel.innerHTML = html;
    panel.classList.add('visible');
  }
}

// ── clearNodeInfo ────────────────────────────────────────────────────────────
function clearNodeInfo() {
  if (cy) cy.nodes().removeClass('selected');
  var panel = document.getElementById('info-panel');
  if (panel) {
    panel.classList.remove('visible');
    panel.innerHTML = '<div class="info-placeholder"><div class="info-ph-icon">&#9672;</div><div class="info-ph-text">Select an artifact type or click any node to see investigation details.</div></div>';
  }
}

// ── setMode ──────────────────────────────────────────────────────────────────
function setMode(mode) {
  activeMode = mode;
  document.querySelectorAll('.mode-card').forEach(function(c) { c.classList.remove('active'); });
  var card = document.querySelector('.mode-card[data-mode="' + mode + '"]');
  if (card) card.classList.add('active');
}

// ── toggleTheme ──────────────────────────────────────────────────────────────
function toggleTheme() {
  var isLight = document.body.classList.toggle('light');
  localStorage.setItem('pivex-theme', isLight ? 'light' : 'dark');
  setLogo(isLight);
}

function setLogo(isLight) {
  var el = document.getElementById('navLogo');
  if (!el) return;
  el.src = isLight
    ? 'https://raw.githubusercontent.com/h3ad-sec/h3ad-sec.github.io/main/logo-light.png'
    : 'https://raw.githubusercontent.com/h3ad-sec/h3ad-sec.github.io/main/logo-dark.png';
}

// ── toggleDrawer / closeDrawer ───────────────────────────────────────────────
function toggleDrawer() {
  var d = document.getElementById('navDrawer');
  if (d) d.classList.toggle('open');
}

function closeDrawer() {
  var d = document.getElementById('navDrawer');
  if (d) d.classList.remove('open');
}

// ── escHtml ──────────────────────────────────────────────────────────────────
function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Matrix canvas animation ──────────────────────────────────────────────────
(function() {
  var canvas = document.getElementById('matrix');
  if (!canvas) return;
  var ctx = canvas.getContext('2d');
  var terms = ['IOC','PIVOT','TTPs','C2','SIEM','EDR','HASH','SCAN',
                'DNS','TI','CVE','YARA','MITRE','HUNT','SOCK','APT',
                'NULL','0x','0xff','REG','SMB','WMI','LSASS','RCE'];
  var cols, drops, fontSize = 13;

  function resize() {
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
    cols  = Math.floor(canvas.width / fontSize);
    drops = Array(cols).fill(1);
  }

  function draw() {
    ctx.fillStyle = 'rgba(6,8,15,0.15)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = 'rgba(0,255,159,0.25)';
    ctx.font = fontSize + 'px Share Tech Mono, monospace';
    for (var i = 0; i < drops.length; i++) {
      var text = terms[Math.floor(Math.random() * terms.length)];
      ctx.fillText(text, i * fontSize, drops[i] * fontSize);
      if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }
  }

  resize();
  window.addEventListener('resize', resize);
  setInterval(draw, 55);
})();

// ── Boot ─────────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', function() {
  var saved = localStorage.getItem('pivex-theme');
  if (saved === 'light') {
    document.body.classList.add('light');
    setLogo(true);
  } else {
    setLogo(false);
  }
  initGraph();
});

window.addEventListener('resize', function() {
  if (cy && graphMode === 'simple') applyCircularLayout();
});
