// PIVEX — app.js  v9.2

// ── State ───────────────────────────────────────────────────────────────────
var cy = null;
var activeArtifact = null;
var pivotPath = [];
var _flowTimer = null;
var _flowOffset = 0;
var _arcMap = null;
var _arcCenter = null;
var _arcRadius = 0;

// ── Category colors ─────────────────────────────────────────────────────────
var CAT_COLORS = {
  network:  { bg: '#00d4ff', border: '#0099bb', text: '#03060a', glow: '#00d4ff' },
  endpoint: { bg: '#00ff9f', border: '#00cc7a', text: '#03060a', glow: '#00ff9f' },
  identity: { bg: '#c084fc', border: '#9333ea', text: '#03060a', glow: '#c084fc' },
  email:    { bg: '#fb923c', border: '#ea580c', text: '#03060a', glow: '#fb923c' },
  cloud:    { bg: '#60a5fa', border: '#2563eb', text: '#03060a', glow: '#60a5fa' }
};

// ── Short labels for graph display ───────────────────────────────────────────
var SHORT_LABELS = {
  ip:'IP', domain:'DOMAIN', fqdn:'FQDN', url:'URL',
  dns_query:'DNS-Q', http_request:'HTTP',
  ssl_cert:'SSL', ssl_certificate:'SSL-CERT', ja3:'JA3',
  user_agent:'UA', network_traffic:'NETFLOW', network_session:'NET-SES',
  hash:'HASH', file:'FILE', file_path:'F-PATH', process:'PROC',
  command_line:'CMD', registry:'REG', scheduled_task:'S-TASK',
  startup_item:'STARTUP', host:'HOST', share:'SHARE',
  event_id:'EVT-ID', vulnerability_id:'CVE',
  user:'USER', identity:'IDENT', rdp_session:'RDP',
  email:'EMAIL', attachment:'ATTACH',
  cloud_resource:'CLOUD'
};

// ── Arc layout config ────────────────────────────────────────────────────────
var ARC_CONFIG = [
  { category: 'network',  count: 12 },
  { category: 'endpoint', count: 12 },
  { category: 'identity', count: 3  },
  { category: 'email',    count: 2  },
  { category: 'cloud',    count: 1  }
];

// ── Artifact order (grouped by category, clockwise) ──────────────────────────
var ARTIFACT_ORDER = [
  'ip','domain','fqdn','url','dns_query','http_request',
  'ssl_cert','ssl_certificate','ja3','user_agent','network_traffic','network_session',
  'hash','file','file_path','process','command_line','registry',
  'scheduled_task','startup_item','host','share','event_id','vulnerability_id',
  'user','identity','rdp_session',
  'email','attachment',
  'cloud_resource'
];

// ── applyCategoryArcLayout ───────────────────────────────────────────────────
function applyCategoryArcLayout() {
  if (!cy) return;
  var container = document.getElementById('cy');
  if (!container) return;
  var W = container.offsetWidth;
  var H = container.offsetHeight;
  if (!W || !H) return;
  var cx = W / 2, cyc = H / 2;
  var radius = Math.min(W, H) * 0.38;

  var totalNodes = ARTIFACT_ORDER.length; // 30
  var CAT_GAP_DEG = 4;                    // small visual gap between categories
  var numCats = ARC_CONFIG.length;        // 5
  var totalGap = numCats * CAT_GAP_DEG;   // 20°
  var available = 360 - totalGap;         // 340°
  var perNode = available / totalNodes;   // ~8.29° per node

  // Build arc map — each category gets exactly count * perNode degrees
  _arcMap = {};
  var cur = -90; // start at top
  ARC_CONFIG.forEach(function(cfg) {
    var span = cfg.count * perNode;
    _arcMap[cfg.category] = {
      startDeg: cur,
      spanDeg: span,
      midDeg: cur + span / 2
    };
    cur += span + CAT_GAP_DEG;
  });
  _arcCenter = { x: cx, y: cyc };
  _arcRadius = radius;

  // Per-category node lists preserving ARTIFACT_ORDER
  var catLists = {};
  ARC_CONFIG.forEach(function(cfg) { catLists[cfg.category] = []; });
  ARTIFACT_ORDER.forEach(function(id) {
    var nd = GRAPH_NODES.find(function(n) { return n.data.id === id; });
    if (nd && catLists[nd.data.category]) catLists[nd.data.category].push(id);
  });

  // Position each node with uniform angular spacing within its category arc
  ARTIFACT_ORDER.forEach(function(id) {
    var node = cy.getElementById(id);
    if (!node.length) return;
    var nd = GRAPH_NODES.find(function(n) { return n.data.id === id; });
    if (!nd) return;
    var cat = nd.data.category;
    var arc = _arcMap[cat];
    if (!arc) return;
    var list = catLists[cat];
    var idx = list.indexOf(id);
    var n = list.length;
    // Node i is centered at startDeg + (i + 0.5) * perNode
    var deg = n === 1
      ? arc.midDeg
      : arc.startDeg + (idx + 0.5) * perNode;
    var rad = deg * Math.PI / 180;
    node.position({ x: cx + radius * Math.cos(rad), y: cyc + radius * Math.sin(rad) });
  });

  cy.fit(cy.nodes(), 44);
  drawCategoryLabels();
}

// ── drawCategoryLabels ───────────────────────────────────────────────────────
function drawCategoryLabels() {
  var overlay = document.getElementById('cat-labels');
  if (!overlay || !cy || !_arcMap || !_arcCenter) return;
  overlay.innerHTML = '';
  var labelR = _arcRadius * 1.24;
  var counts = {};
  ARC_CONFIG.forEach(function(c) { counts[c.category] = c.count; });

  Object.keys(_arcMap).forEach(function(cat) {
    var arc = _arcMap[cat];
    var midRad = arc.midDeg * Math.PI / 180;
    var mx = _arcCenter.x + labelR * Math.cos(midRad);
    var my = _arcCenter.y + labelR * Math.sin(midRad);
    var rendered = cy.modelToRenderedPosition({ x: mx, y: my });
    var el = document.createElement('div');
    el.className = 'cat-arc-label cat-arc-' + cat;
    el.style.left = rendered.x + 'px';
    el.style.top  = rendered.y + 'px';
    el.innerHTML = cat.toUpperCase() +
      '<span class="cat-arc-count">&thinsp;&middot;&thinsp;' + counts[cat] + '</span>';
    overlay.appendChild(el);
  });
}

// ── startEdgeFlow / stopEdgeFlow ─────────────────────────────────────────────
function startEdgeFlow() {
  stopEdgeFlow();
  _flowOffset = 0;
  _flowTimer = setInterval(function() {
    _flowOffset = (_flowOffset + 1) % 30;
    if (cy) cy.edges('.highlighted').style('line-dash-offset', -_flowOffset);
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
    el.innerHTML = '<span>30 artifacts</span><span>83 pivots</span>';
  } else {
    var pathData = ARTIFACT_PATHS[selectedType];
    var nc = pathData ? pathData.nodes.length - 1 : 0;
    el.innerHTML = '<span>' + (SHORT_LABELS[selectedType] || selectedType) + '</span>' +
      '<span>' + nc + ' connected</span>';
  }
}

// ── initGraph ───────────────────────────────────────────────────────────────
function initGraph() {
  var container = document.getElementById('cy');
  if (!container) return;

  cy = cytoscape({
    container: container,
    elements: GRAPH_NODES.concat(GRAPH_EDGES),
    style: [
      // Base node
      { selector: 'node', style: {
          'shape': 'roundrectangle',
          'label': function(n) { return SHORT_LABELS[n.data('id')] || n.data('label'); },
          'font-family': 'Share Tech Mono, monospace',
          'font-size': '9px',
          'font-weight': 'bold',
          'letter-spacing': '0.04em',
          'padding': '5px 8px',
          'width': 'label',
          'height': 'label',
          'text-valign': 'center',
          'text-halign': 'center',
          'background-color': '#0e1a2c',
          'border-color': '#2a4060',
          'border-width': 1.5,
          'color': '#8bacc8',
          'transition-property': 'opacity shadow-blur shadow-opacity border-color border-width',
          'transition-duration': '0.18s',
          'cursor': 'pointer'
      }},
      // Category colors
      { selector: 'node[category = "network"]',
        style: { 'background-color': '#00d4ff', 'border-color': '#0099bb', 'color': '#03060a', 'border-width': 2 }},
      { selector: 'node[category = "endpoint"]',
        style: { 'background-color': '#00ff9f', 'border-color': '#00cc7a', 'color': '#03060a', 'border-width': 2 }},
      { selector: 'node[category = "identity"]',
        style: { 'background-color': '#c084fc', 'border-color': '#9333ea', 'color': '#03060a', 'border-width': 2 }},
      { selector: 'node[category = "email"]',
        style: { 'background-color': '#fb923c', 'border-color': '#ea580c', 'color': '#03060a', 'border-width': 2 }},
      { selector: 'node[category = "cloud"]',
        style: { 'background-color': '#60a5fa', 'border-color': '#2563eb', 'color': '#03060a', 'border-width': 2 }},
      // Default edges — very subtle
      { selector: 'edge', style: {
          'width': 1,
          'opacity': 0.07,
          'line-color': '#3a5470',
          'target-arrow-color': '#3a5470',
          'target-arrow-shape': 'triangle',
          'arrow-scale': 0.7,
          'curve-style': 'bezier',
          'transition-property': 'opacity width line-color',
          'transition-duration': '0.18s'
      }},
      // Highlighted (path or first-hop)
      { selector: 'node.highlighted', style: {
          'opacity': 1,
          'border-width': 3,
          'shadow-blur': 20,
          'shadow-opacity': 0.75,
          'z-index': 10
      }},
      { selector: 'node[category = "network"].highlighted',  style: { 'border-color': '#00d4ff', 'shadow-color': '#00d4ff' }},
      { selector: 'node[category = "endpoint"].highlighted', style: { 'border-color': '#00ff9f', 'shadow-color': '#00ff9f' }},
      { selector: 'node[category = "identity"].highlighted', style: { 'border-color': '#c084fc', 'shadow-color': '#c084fc' }},
      { selector: 'node[category = "email"].highlighted',    style: { 'border-color': '#fb923c', 'shadow-color': '#fb923c' }},
      { selector: 'node[category = "cloud"].highlighted',    style: { 'border-color': '#60a5fa', 'shadow-color': '#60a5fa' }},
      { selector: 'edge.highlighted', style: {
          'opacity': 1, 'width': 2.5,
          'line-style': 'dashed', 'line-dash-pattern': [6, 3], 'line-dash-offset': 0,
          'arrow-scale': 0.9
      }},
      // Next pivot — reachable from path endpoint, not yet in path
      { selector: 'node.next-pivot', style: {
          'opacity': 0.5,
          'border-width': 2,
          'z-index': 5
      }},
      // Dim state
      { selector: 'node.dimmed', style: { 'opacity': 0.055 }},
      { selector: 'edge.dimmed', style: { 'opacity': 0.015 }},
      // Selected (node in path)
      { selector: 'node.selected', style: { 'border-width': 3.5, 'z-index': 20 }}
    ],
    layout: { name: 'null' },
    userZoomingEnabled: true,
    userPanningEnabled: true,
    boxSelectionEnabled: false,
    minZoom: 0.3,
    maxZoom: 3
  });

  applyCategoryArcLayout();
  updateStats(null);

  cy.on('tap', 'node', function(evt) {
    var node = evt.target;
    var id = node.id();
    // If we have an active path and this node is a reachable next pivot → extend path
    if (pivotPath.length > 0 && node.hasClass('next-pivot')) {
      extendPivotPath(id);
    } else {
      // Start a new path from this node
      selectArtifact(id);
    }
  });

  cy.on('tap', function(evt) {
    if (evt.target === cy) {
      clearPivotPath();
    }
  });

  cy.on('viewport', function() { drawCategoryLabels(); });
}

// ── selectArtifact ──────────────────────────────────────────────────────────
function selectArtifact(type) {
  stopEdgeFlow();

  // Toggle off if same chip clicked and path is just that one node
  if (pivotPath.length === 1 && pivotPath[0] === type && activeArtifact === type) {
    resetHighlight();
    pivotPath = [];
    activeArtifact = null;
    _setActiveChip('all');
    updateStats(null);
    renderPivotPath();
    _clearPanel();
    return;
  }

  activeArtifact = type;
  pivotPath = [type];
  _setActiveChip(type);
  if (!cy) return;
  updateStats(type);

  _applyPathHighlight();
  startEdgeFlow();

  // Center the selected node in the viewport
  var artNode = cy.getElementById(type);
  cy.stop();
  cy.animate({ center: { eles: artNode }, duration: 320, easing: 'ease-in-out-sine' });

  showNodeInfo(artNode);
  renderPivotPath();
}

// ── extendPivotPath ──────────────────────────────────────────────────────────
function extendPivotPath(id) {
  if (!cy) return;
  // Don't add if already in path
  if (pivotPath.indexOf(id) >= 0) return;

  pivotPath.push(id);
  activeArtifact = id;
  _setActiveChip(id);
  updateStats(id);

  stopEdgeFlow();
  _applyPathHighlight();
  startEdgeFlow();

  // Center on the new endpoint
  var node = cy.getElementById(id);
  cy.stop();
  cy.animate({ center: { eles: node }, duration: 320, easing: 'ease-in-out-sine' });

  showNodeInfo(node);
  renderPivotPath();
}

// ── _applyPathHighlight ──────────────────────────────────────────────────────
function _applyPathHighlight() {
  if (!cy || pivotPath.length === 0) return;

  var lastId = pivotPath[pivotPath.length - 1];
  var lastNode = cy.getElementById(lastId);

  // Collect path node set
  var pathNodeSet = cy.collection();
  pivotPath.forEach(function(id) {
    pathNodeSet = pathNodeSet.union(cy.getElementById(id));
  });

  // Collect path edge set (consecutive pairs in path)
  var pathEdgeSet = cy.collection();
  for (var i = 0; i < pivotPath.length - 1; i++) {
    var a = pivotPath[i], b = pivotPath[i + 1];
    var fwd = cy.edges('[source = "' + a + '"][target = "' + b + '"]');
    var rev = cy.edges('[source = "' + b + '"][target = "' + a + '"]');
    pathEdgeSet = pathEdgeSet.union(fwd).union(rev);
  }

  // Next pivots: neighbors of last node not already in path
  var lastConnEdges = lastNode.connectedEdges();
  var lastConnNodes = lastConnEdges.connectedNodes();
  var nextPivotSet = lastConnNodes.difference(pathNodeSet);

  // Edges from last node to next pivots
  var nextPivotEdges = lastConnEdges.filter(function(e) {
    return nextPivotSet.has(e.source()) || nextPivotSet.has(e.target());
  });

  var lastNd = GRAPH_NODES.find(function(n) { return n.data.id === lastId; });
  var lastColor = lastNd && CAT_COLORS[lastNd.data.category]
    ? CAT_COLORS[lastNd.data.category].bg : '#ffd60a';

  cy.batch(function() {
    cy.elements().removeStyle();
    cy.nodes().removeClass('highlighted dimmed selected next-pivot');
    cy.edges().removeClass('highlighted dimmed');

    // Path nodes: highlighted
    pathNodeSet.addClass('highlighted');
    // Path edges: highlighted + colored per source category
    pathEdgeSet.addClass('highlighted');

    // Color each path edge by its source node's category
    for (var j = 0; j < pivotPath.length - 1; j++) {
      var srcId = pivotPath[j];
      var tgtId = pivotPath[j + 1];
      var srcNd = GRAPH_NODES.find(function(n) { return n.data.id === srcId; });
      var edgeColor = srcNd && CAT_COLORS[srcNd.data.category]
        ? CAT_COLORS[srcNd.data.category].bg : '#ffd60a';
      var edges = cy.edges('[source = "' + srcId + '"][target = "' + tgtId + '"]')
        .union(cy.edges('[source = "' + tgtId + '"][target = "' + srcId + '"]'));
      edges.style({ 'line-color': edgeColor, 'target-arrow-color': edgeColor });
    }

    // Next pivot nodes: semi-visible
    nextPivotSet.addClass('next-pivot');

    // Next pivot edges: subtle in last node's color
    nextPivotEdges.style({
      'opacity': 0.3,
      'line-color': lastColor,
      'target-arrow-color': lastColor
    });

    // Dim everything else
    cy.nodes().difference(pathNodeSet).difference(nextPivotSet).addClass('dimmed');
    cy.edges().difference(pathEdgeSet).difference(nextPivotEdges).addClass('dimmed');

    // Last node in path: strongest glow
    lastNode.style({
      'shadow-color': lastColor,
      'shadow-blur': 32,
      'shadow-opacity': 0.9,
      'border-width': 3.5
    });

    // Earlier path nodes: moderate glow
    pathNodeSet.difference(lastNode).forEach(function(n) {
      var nd = GRAPH_NODES.find(function(g) { return g.data.id === n.id(); });
      var c = nd && CAT_COLORS[nd.data.category] ? CAT_COLORS[nd.data.category].bg : '#ffd60a';
      n.style({ 'shadow-color': c, 'shadow-blur': 12, 'shadow-opacity': 0.55 });
    });
  });
}

function _setActiveChip(type) {
  document.querySelectorAll('.artifact-chip').forEach(function(b) { b.classList.remove('active'); });
  var chip = document.querySelector('.artifact-chip[data-type="' + type + '"]');
  if (chip) {
    chip.classList.add('active');
    // Scroll the chip into view in the topbar
    chip.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
  }
}

// ── selectAll ───────────────────────────────────────────────────────────────
function selectAll() {
  stopEdgeFlow();
  resetHighlight();
  pivotPath = [];
  activeArtifact = null;
  _setActiveChip('all');
  updateStats(null);
  renderPivotPath();
  _clearPanel();
}

// ── clearPivotPath ───────────────────────────────────────────────────────────
function clearPivotPath() {
  stopEdgeFlow();
  resetHighlight();
  pivotPath = [];
  activeArtifact = null;
  _setActiveChip('all');
  updateStats(null);
  renderPivotPath();
  _clearPanel();
}

// ── resetHighlight ──────────────────────────────────────────────────────────
function resetHighlight() {
  if (!cy) return;
  cy.batch(function() {
    cy.elements().removeStyle();
    cy.nodes().removeClass('highlighted dimmed selected next-pivot');
    cy.edges().removeClass('highlighted dimmed');
  });
}

// ── renderPivotPath ──────────────────────────────────────────────────────────
function renderPivotPath() {
  var bar   = document.getElementById('pivotPathBar');
  var trail = document.getElementById('pivotPathTrail');
  if (!bar || !trail) return;

  if (pivotPath.length < 2) {
    bar.classList.remove('visible');
    trail.innerHTML = '';
    return;
  }

  bar.classList.add('visible');
  trail.innerHTML = pivotPath.map(function(id, i) {
    var nd = GRAPH_NODES.find(function(n) { return n.data.id === id; });
    var label = nd ? nd.data.label : id;
    var cat   = nd ? nd.data.category : '';
    var color = CAT_COLORS[cat] ? CAT_COLORS[cat].bg : '#e2eeff';
    var isLast = i === pivotPath.length - 1;
    var cls = isLast ? 'path-node path-node-active' : 'path-node path-node-visited';
    var html = '<span class="' + cls + '" style="color:' + color + '">' + escHtml(label) + '</span>';
    if (!isLast) html += '<span class="path-arrow">&#8594;</span>';
    return html;
  }).join('');
}

// ── showNodeInfo ─────────────────────────────────────────────────────────────
function showNodeInfo(node) {
  if (!node) return;
  cy.nodes().removeClass('selected');
  node.addClass('selected');

  var d = node.data();
  var catBadge = '';
  if (d.category && CAT_COLORS[d.category]) {
    catBadge = '<span class="info-cat-badge" style="background:' +
      CAT_COLORS[d.category].bg + ';color:' + CAT_COLORS[d.category].text + '">' +
      d.category + '</span>';
  }
  var pivotsHtml = '';
  if (d.pivots && d.pivots.length) {
    pivotsHtml = '<div class="info-section"><div class="info-section-label">PIVOT TO</div>' +
      '<ul class="info-list">' +
      d.pivots.map(function(p) { return '<li>' + escHtml(p) + '</li>'; }).join('') +
      '</ul></div>';
  }
  var sourcesHtml = d.sources
    ? '<div class="info-section"><div class="info-section-label">DATA SOURCES</div>' +
      '<div class="info-sources">' + escHtml(d.sources) + '</div></div>'
    : '';

  var html = '<div class="info-header">' +
    '<span class="info-type-badge info-type-artifact">Artifact</span>' +
    catBadge +
    '<button class="info-close" onclick="clearPivotPath()">&#x2715;</button>' +
    '</div>' +
    '<div class="info-inner">' +
    '<div class="info-title">' + escHtml(d.label || d.id) + '</div>';
  if (d.desc) html += '<div class="info-desc">' + escHtml(d.desc) + '</div>';
  html += sourcesHtml + pivotsHtml;
  if (pivotPath.length > 0) {
    html += '<div class="info-hint">Click a highlighted node to extend pivot path.</div>';
  }
  html += '</div>';

  var panel = document.getElementById('info-panel');
  if (panel) { panel.innerHTML = html; panel.classList.add('visible'); }
}

// ── clearNodeInfo ────────────────────────────────────────────────────────────
function clearNodeInfo() {
  if (cy) cy.nodes().removeClass('selected');
  _clearPanel();
}

function _clearPanel() {
  var panel = document.getElementById('info-panel');
  if (panel) {
    panel.classList.remove('visible');
    panel.innerHTML = '<div class="info-placeholder">' +
      '<div class="info-ph-icon">&#9672;</div>' +
      '<div class="info-ph-text">Select an artifact or click any node.</div>' +
      '</div>';
  }
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
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── Matrix canvas ─────────────────────────────────────────────────────────────
(function() {
  var canvas = document.getElementById('matrix');
  if (!canvas) return;
  var ctx = canvas.getContext('2d');
  var terms = ['IOC','PIVOT','TTPs','C2','SIEM','EDR','HASH','SCAN',
                'DNS','TI','CVE','YARA','MITRE','HUNT','SOCK','APT',
                'NULL','0x','0xff','REG','SMB','WMI','LSASS','RCE'];
  var cols, drops, fs = 13;
  function resize() {
    canvas.width = window.innerWidth; canvas.height = window.innerHeight;
    cols = Math.floor(canvas.width / fs); drops = Array(cols).fill(1);
  }
  function draw() {
    ctx.fillStyle = 'rgba(6,8,15,0.15)'; ctx.fillRect(0,0,canvas.width,canvas.height);
    ctx.fillStyle = 'rgba(0,255,159,0.22)'; ctx.font = fs + 'px Share Tech Mono,monospace';
    for (var i = 0; i < drops.length; i++) {
      ctx.fillText(terms[Math.floor(Math.random()*terms.length)], i*fs, drops[i]*fs);
      if (drops[i]*fs > canvas.height && Math.random() > 0.975) drops[i] = 0;
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
  if (saved === 'light') { document.body.classList.add('light'); setLogo(true); }
  else { setLogo(false); }
  initGraph();
});

window.addEventListener('resize', function() {
  if (cy) applyCategoryArcLayout();
});
