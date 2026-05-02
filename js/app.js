// PIVEX — app.js
// All logic global (no modules). Loaded after graph-data.js.

// ── State ───────────────────────────────────────────────────────────────────
var cy = null;
var activeArtifact = null;
var activeMode = 'reactive';

// ── Node color map ──────────────────────────────────────────────────────────
var NODE_COLORS = {
  artifact:    { bg: '#00ff9f', border: '#00cc7a', text: '#06080f' },
  enrichment:  { bg: '#3b82f6', border: '#2563eb', text: '#ffffff' },
  context:     { bg: '#a855f7', border: '#9333ea', text: '#ffffff' },
  pivot:       { bg: '#ffd60a', border: '#c9a800', text: '#06080f' },
  correlation: { bg: '#f97316', border: '#c95d0a', text: '#ffffff' },
  action:      { bg: '#ec4899', border: '#c4186e', text: '#ffffff' }
};

var DECISION_COLORS = {
  'dec-malicious':  { bg: '#ff3b5c', border: '#cc2244', text: '#ffffff' },
  'dec-suspicious': { bg: '#ffd60a', border: '#c9a800', text: '#06080f' },
  'dec-benign':     { bg: '#00ff9f', border: '#00cc7a', text: '#06080f' },
  'dec-unknown':    { bg: '#7d8fb3', border: '#5a6e92', text: '#ffffff' }
};

// ── Helper: get node color ──────────────────────────────────────────────────
function nodeColor(node) {
  var id = node.data('id');
  var type = node.data('type');
  if (type === 'decision' && DECISION_COLORS[id]) return DECISION_COLORS[id];
  return NODE_COLORS[type] || { bg: '#334155', border: '#475569', text: '#ffffff' };
}

// ── initGraph ───────────────────────────────────────────────────────────────
function initGraph() {
  cy = cytoscape({
    container: document.getElementById('cy'),
    elements: {
      nodes: GRAPH_NODES,
      edges: GRAPH_EDGES
    },
    style: [
      // ── Base node ──
      {
        selector: 'node',
        style: {
          'shape': 'roundrectangle',
          'label': 'data(label)',
          'font-family': '"Share Tech Mono", monospace',
          'font-size': '10px',
          'padding': '8px',
          'width': 'label',
          'height': 'label',
          'text-valign': 'center',
          'text-halign': 'center',
          'text-wrap': 'wrap',
          'text-max-width': '100px',
          'background-color': function(ele) { return nodeColor(ele).bg; },
          'border-color': function(ele) { return nodeColor(ele).border; },
          'color': function(ele) { return nodeColor(ele).text; },
          'border-width': 1.5,
          'opacity': 1
        }
      },
      // ── Artifact nodes larger font ──
      {
        selector: 'node[type = "artifact"]',
        style: {
          'font-size': '11px',
          'border-width': 2
        }
      },
      // ── Base edge ──
      {
        selector: 'edge',
        style: {
          'width': 1,
          'opacity': 0.35,
          'line-color': '#3a5470',
          'target-arrow-color': '#3a5470',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'label': 'data(label)',
          'font-family': '"Share Tech Mono", monospace',
          'font-size': '7px',
          'color': '#62809c',
          'text-opacity': 0.7,
          'edge-text-rotation': 'autorotate'
        }
      },
      // ── Cross-pivot edges ──
      {
        selector: 'edge[crossPivot]',
        style: {
          'width': 2,
          'line-style': 'dashed',
          'line-color': '#00ff9f',
          'target-arrow-color': '#00ff9f',
          'opacity': 0.7,
          'color': '#00ff9f'
        }
      },
      // ── Highlighted nodes ──
      {
        selector: 'node.highlighted',
        style: {
          'opacity': 1,
          'border-color': '#00ff9f',
          'border-width': 2.5
        }
      },
      // ── Highlighted edges ──
      {
        selector: 'edge.highlighted',
        style: {
          'opacity': 1,
          'width': 2,
          'line-color': '#00ff9f',
          'target-arrow-color': '#00ff9f',
          'color': '#00ff9f',
          'text-opacity': 1
        }
      },
      // ── Dimmed nodes ──
      {
        selector: 'node.dimmed',
        style: {
          'opacity': 0.07
        }
      },
      // ── Dimmed edges ──
      {
        selector: 'edge.dimmed',
        style: {
          'opacity': 0.07
        }
      },
      // ── Selected node ──
      {
        selector: 'node.selected',
        style: {
          'border-color': '#ffd60a',
          'border-width': 3
        }
      }
    ],
    layout: {
      name: 'cose-bilkent',
      animate: false,
      nodeDimensionsIncludeLabels: true,
      idealEdgeLength: 100,
      nodeRepulsion: 6000,
      gravity: 0.25,
      numIter: 2500
    }
  });

  // ── Tap node ──
  cy.on('tap', 'node', function(evt) {
    showNodeInfo(evt.target);
  });

  // ── Tap background ──
  cy.on('tap', function(evt) {
    if (evt.target === cy) {
      clearNodeInfo();
    }
  });
}

// ── selectArtifact ──────────────────────────────────────────────────────────
function selectArtifact(type) {
  if (activeArtifact === type) {
    resetHighlight();
    activeArtifact = null;
    document.querySelectorAll('.artifact-btn').forEach(function(b) {
      b.classList.remove('active');
    });
    // Re-activate ALL
    var allBtn = document.querySelector('.artifact-btn[data-type="all"]');
    if (allBtn) allBtn.classList.add('active');
    return;
  }

  activeArtifact = type;

  // Update button states
  document.querySelectorAll('.artifact-btn').forEach(function(b) {
    b.classList.remove('active');
  });
  var btn = document.querySelector('.artifact-btn[data-type="' + type + '"]');
  if (btn) btn.classList.add('active');

  var pathData = ARTIFACT_PATHS[type];
  if (!pathData || !cy) return;

  var pathNodeIds = pathData.nodes;

  // Highlight path nodes, dim everything else
  cy.batch(function() {
    cy.nodes().forEach(function(n) {
      n.removeClass('highlighted dimmed selected');
      if (pathNodeIds.indexOf(n.data('id')) !== -1) {
        n.addClass('highlighted');
      } else {
        n.addClass('dimmed');
      }
    });

    cy.edges().forEach(function(e) {
      e.removeClass('highlighted dimmed');
      var src = e.data('source');
      var tgt = e.data('target');
      if (pathNodeIds.indexOf(src) !== -1 && pathNodeIds.indexOf(tgt) !== -1) {
        e.addClass('highlighted');
      } else {
        e.addClass('dimmed');
      }
    });
  });

  showArtifactInfo(type);
}

// ── selectAll ───────────────────────────────────────────────────────────────
function selectAll() {
  resetHighlight();
  activeArtifact = null;
  document.querySelectorAll('.artifact-btn').forEach(function(b) {
    b.classList.remove('active');
  });
  var allBtn = document.querySelector('.artifact-btn[data-type="all"]');
  if (allBtn) allBtn.classList.add('active');

  var panel = document.getElementById('info-panel');
  if (panel) {
    panel.classList.remove('visible');
    panel.innerHTML = '<div class="info-placeholder"><div class="info-ph-icon">&#9672;</div><div class="info-ph-text">Select an artifact type above or click any node in the graph to see investigation details.</div></div>';
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

// ── showNodeInfo ─────────────────────────────────────────────────────────────
function showNodeInfo(node) {
  if (!node) return;

  // Remove selected from all, add to this
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

  var html = '<div class="info-header">' +
    '<span class="info-type-badge info-type-' + escHtml(d.type || '') + '">' + escHtml(typeLabel) + '</span>' +
    '<button class="info-close" onclick="clearNodeInfo()">&#x2715;</button>' +
    '</div>' +
    '<div class="info-title">' + escHtml(d.label || d.id) + '</div>';

  if (d.desc) {
    html += '<div class="info-desc">' + escHtml(d.desc) + '</div>';
  }

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

  var html = '<div class="info-header">' +
    '<span class="info-type-badge info-type-artifact">Artifact Path</span>' +
    '<button class="info-close" onclick="clearNodeInfo()">&#x2715;</button>' +
    '</div>' +
    '<div class="info-title">' + escHtml(p.label) + ' Investigation</div>' +
    '<div class="info-section">' +
      '<div class="info-section-label">PATH NODES</div>' +
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
    panel.innerHTML = '<div class="info-placeholder"><div class="info-ph-icon">&#9672;</div><div class="info-ph-text">Select an artifact type above or click any node in the graph to see investigation details.</div></div>';
  }
}

// ── setMode ──────────────────────────────────────────────────────────────────
function setMode(mode) {
  activeMode = mode;
  document.querySelectorAll('.mode-card').forEach(function(c) {
    c.classList.remove('active');
  });
  var card = document.querySelector('.mode-card[data-mode="' + mode + '"]');
  if (card) card.classList.add('active');
}

// ── toggleTheme ──────────────────────────────────────────────────────────────
function toggleTheme() {
  var isLight = document.body.classList.toggle('light');
  localStorage.setItem('pivex-theme', isLight ? 'light' : 'dark');
  setLogo(isLight);
}

// ── setLogo ──────────────────────────────────────────────────────────────────
function setLogo(isLight) {
  var el = document.getElementById('navLogo');
  if (!el) return;
  el.src = isLight
    ? 'https://h3ad-sec.github.io/assets/logo-dark.png'
    : 'https://h3ad-sec.github.io/assets/logo-light.png';
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

  var chars = ['Pivot','IOC','IP','Hash','Domain','TTP','T1566','T1071','T1059','T1003','T1021',
    'MITRE','ATT&CK','C2','DNS','EDR','SIEM','VT','OTX','Enrich','Correlate','Hunt',
    'Artifact','Process','User','Host','Email','URL','Lateral','Persist'];

  var colW = 18;
  var cols, drops;

  function resize() {
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    cols = Math.floor(canvas.width / colW);
    drops = [];
    for (var i = 0; i < cols; i++) {
      drops[i] = Math.floor(Math.random() * -canvas.height / 14);
    }
  }

  resize();
  window.addEventListener('resize', resize);

  function draw() {
    var light = document.body.classList.contains('light');
    ctx.fillStyle = light ? 'rgba(238,242,248,0.1)' : 'rgba(6,8,14,0.14)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.fillStyle = light ? '#004db8' : '#00ff9f';
    ctx.font = '11px monospace';

    for (var i = 0; i < drops.length; i++) {
      var word = chars[Math.floor(Math.random() * chars.length)];
      var x = i * colW;
      var y = drops[i] * 14;
      if (y > 0 && y < canvas.height) {
        ctx.fillText(word, x, y);
      }
      drops[i]++;
      if (drops[i] * 14 > canvas.height && Math.random() > 0.975) {
        drops[i] = Math.floor(Math.random() * -20);
      }
    }
  }

  setInterval(draw, 45);
})();

// ── DOMContentLoaded ─────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', function() {
  // Apply saved theme
  var savedTheme = localStorage.getItem('pivex-theme');
  if (savedTheme === 'light') {
    document.body.classList.add('light');
    setLogo(true);
  } else {
    setLogo(false);
  }

  // Close drawer on outside click
  document.addEventListener('click', function(e) {
    var drawer = document.getElementById('navDrawer');
    var hamburger = document.querySelector('.nav-hamburger');
    if (drawer && hamburger) {
      if (!drawer.contains(e.target) && !hamburger.contains(e.target)) {
        drawer.classList.remove('open');
      }
    }
  });

  // Init graph
  initGraph();

  // Activate ALL button
  var allBtn = document.querySelector('.artifact-btn[data-type="all"]');
  if (allBtn) allBtn.classList.add('active');

  // Activate reactive mode card
  var reactCard = document.querySelector('.mode-card[data-mode="reactive"]');
  if (reactCard) reactCard.classList.add('active');
});
