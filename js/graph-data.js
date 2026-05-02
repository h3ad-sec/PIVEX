// PIVEX — graph-data.js
// Global constants referenced by app.js. No modules.

const GRAPH_NODES = [
  // ── ARTIFACT NODES ──────────────────────────────────────────────────
  {
    data: {
      id: 'ip', type: 'artifact', label: 'IP Address',
      desc: 'An IP address observed in logs, alerts, or network telemetry.',
      sources: 'Firewall · SIEM · NetFlow · Proxy',
      pivots: ['Passive DNS', 'Related IPs (same ASN)', 'URLs served', 'C2 check', 'DHCP asset lookup (→ Host)']
    }
  },
  {
    data: {
      id: 'domain', type: 'artifact', label: 'Domain',
      desc: 'A domain name seen in DNS queries, HTTP traffic, or email headers.',
      sources: 'DNS logs · Proxy · Email Gateway',
      pivots: ['Resolved IPs', 'Subdomains', 'URLs on domain', 'WHOIS history']
    }
  },
  {
    data: {
      id: 'url', type: 'artifact', label: 'URL',
      desc: 'A full URL from web proxy, email links, or browser history.',
      sources: 'Proxy logs · Email Gateway · Browser history',
      pivots: ['Hosting domain', 'Hosting IP', 'Downloaded payload (hash)']
    }
  },
  {
    data: {
      id: 'hash', type: 'artifact', label: 'File Hash',
      desc: 'MD5/SHA1/SHA256 of a file observed on disk or in memory.',
      sources: 'EDR · AV · Sandbox · Email attachment scan',
      pivots: ['Associated processes', 'Dropped files', 'C2 IPs/domains', 'Malware family']
    }
  },
  {
    data: {
      id: 'process', type: 'artifact', label: 'Process',
      desc: 'A running or historical process with command line, parent, and hash context.',
      sources: 'EDR · Sysmon (Event ID 1) · Windows Security 4688',
      pivots: ['Child processes', 'Network connections', 'Dropped files', 'Parent process', 'Binary hash', 'Process owner (→ User)']
    }
  },
  {
    data: {
      id: 'user', type: 'artifact', label: 'User',
      desc: 'A user account involved in the activity — local, domain, or service account.',
      sources: 'AD logs · IAM · Okta · SIEM',
      pivots: ['Hosts logged into', 'Lateral movement paths', 'Privilege escalation', 'Login source IPs (→ IP)', 'Email activity (→ Email)']
    }
  },
  {
    data: {
      id: 'email', type: 'artifact', label: 'Email',
      desc: 'A phishing or suspicious email with headers, body, URLs, and attachments.',
      sources: 'Email Gateway · O365 Message Trace · SIEM',
      pivots: ['Sender IP', 'Embedded URLs', 'Attachments (hash)', 'Recipient user']
    }
  },
  {
    data: {
      id: 'host', type: 'artifact', label: 'Host',
      desc: 'An endpoint, server, or workstation involved in the incident.',
      sources: 'EDR · SIEM · AD · Vulnerability Scanner',
      pivots: ['Running processes', 'Logged-in users', 'Network connections']
    }
  },

  // ── ENRICHMENT NODES ────────────────────────────────────────────────
  {
    data: {
      id: 'rep', type: 'enrichment', label: 'Reputation',
      desc: 'Threat reputation scores from VT, OTX, AbuseIPDB, and other feeds.',
      sources: 'VirusTotal · OTX · AbuseIPDB'
    }
  },
  {
    data: {
      id: 'whois', type: 'enrichment', label: 'WHOIS / DNS',
      desc: 'Registration data, NS records, MX records, A/AAAA resolution.',
      sources: 'WHOIS · Passive DNS · RiskIQ'
    }
  },
  {
    data: {
      id: 'asn', type: 'enrichment', label: 'ASN / Geo',
      desc: 'Autonomous System Number, geolocation, hosting provider, and org info.',
      sources: 'Shodan · IPinfo · MaxMind · Censys'
    }
  },
  {
    data: {
      id: 'file-meta', type: 'enrichment', label: 'File Metadata',
      desc: 'PE headers, compile time, imphash, rich header, code signing status.',
      sources: 'VT file report · PE analysis · Sandbox'
    }
  },
  {
    data: {
      id: 'sandbox', type: 'enrichment', label: 'Sandbox',
      desc: 'Dynamic analysis — runtime behavior, network IOCs, registry, dropped files.',
      sources: 'Any.run · Hybrid Analysis · VT Sandbox'
    }
  },
  {
    data: {
      id: 'proc-meta', type: 'enrichment', label: 'Process Info',
      desc: 'Command line args, binary path, signing status, parent/child tree.',
      sources: 'EDR · Sysmon · Windows Event Logs'
    }
  },

  // ── CONTEXT NODES ───────────────────────────────────────────────────
  {
    data: {
      id: 'first-seen', type: 'context', label: 'First/Last Seen',
      desc: 'When the artifact was first and last observed.',
      sources: 'SIEM timeline · EDR history'
    }
  },
  {
    data: {
      id: 'frequency', type: 'context', label: 'Frequency',
      desc: 'How often the artifact appears — beaconing intervals, login frequency.',
      sources: 'SIEM aggregation · Proxy logs'
    }
  },
  {
    data: {
      id: 'environment', type: 'context', label: 'Environment',
      desc: 'Whether the host/user is production, dev, user workstation, or server.',
      sources: 'CMDB · AD OU · Asset inventory'
    }
  },
  {
    data: {
      id: 'ti-tags', type: 'context', label: 'TI Tags',
      desc: 'Threat intel tags: malware family, actor, campaign, TTPs.',
      sources: 'OTX pulses · VT community · MISP · ISACs'
    }
  },
  {
    data: {
      id: 'mitre', type: 'context', label: 'MITRE TTP',
      desc: 'ATT&CK technique mapping for the observed behavior or artifact.',
      sources: 'Sigma rules · EDR detections · HYPOS'
    }
  },

  // ── PIVOT NODES ─────────────────────────────────────────────────────
  {
    data: {
      id: 'p-ip', type: 'pivot', label: 'Related IPs',
      desc: 'IPs sharing same ASN, infra, SSL cert, or campaign.'
    }
  },
  {
    data: {
      id: 'p-domain', type: 'pivot', label: 'Related Domains',
      desc: 'Domains resolving to same IP, registrant, SSL cert, or DGA pattern.'
    }
  },
  {
    data: {
      id: 'p-url', type: 'pivot', label: 'Related URLs',
      desc: 'URLs on the same domain or IP, or serving similar payloads.'
    }
  },
  {
    data: {
      id: 'p-file', type: 'pivot', label: 'Related Files',
      desc: 'Files with same imphash, code-signing cert, or dropped by same parent.'
    }
  },
  {
    data: {
      id: 'p-process', type: 'pivot', label: 'Related Processes',
      desc: 'Child/parent processes, spawned commands, or processes with same hash.'
    }
  },
  {
    data: {
      id: 'p-user', type: 'pivot', label: 'Related Users',
      desc: 'Users on same host, same credential, or same access scope.'
    }
  },
  {
    data: {
      id: 'p-host', type: 'pivot', label: 'Related Hosts',
      desc: 'Hosts with same user activity or lateral movement destination.'
    }
  },

  // ── CORRELATION NODES ───────────────────────────────────────────────
  {
    data: {
      id: 'corr-asn', type: 'correlation', label: 'Same ASN / Infra',
      desc: 'Multiple IPs/domains hosted on the same ASN or infrastructure block.'
    }
  },
  {
    data: {
      id: 'corr-ssl', type: 'correlation', label: 'Same SSL Cert',
      desc: 'Domains/IPs sharing an SSL certificate — strong infra cluster signal.'
    }
  },
  {
    data: {
      id: 'corr-malware', type: 'correlation', label: 'Same Malware',
      desc: 'Files/processes attributed to the same malware family.'
    }
  },
  {
    data: {
      id: 'corr-campaign', type: 'correlation', label: 'Same Campaign',
      desc: 'Multiple indicators linked to the same threat campaign or actor.'
    }
  },
  {
    data: {
      id: 'corr-time', type: 'correlation', label: 'Temporal Cluster',
      desc: 'Events temporally clustered — simultaneous activity across hosts or users.'
    }
  },

  // ── DECISION NODES ──────────────────────────────────────────────────
  {
    data: {
      id: 'dec-malicious', type: 'decision', label: 'Malicious',
      desc: 'High confidence — confirmed threat. Proceed with containment.'
    }
  },
  {
    data: {
      id: 'dec-suspicious', type: 'decision', label: 'Suspicious',
      desc: 'Medium confidence — requires further investigation before action.'
    }
  },
  {
    data: {
      id: 'dec-benign', type: 'decision', label: 'Benign',
      desc: 'Low/no threat signal — likely false positive or expected behavior.'
    }
  },
  {
    data: {
      id: 'dec-unknown', type: 'decision', label: 'Unknown',
      desc: 'Insufficient data to determine verdict. Expand enrichment.'
    }
  },

  // ── ACTION NODES ────────────────────────────────────────────────────
  {
    data: {
      id: 'act-block', type: 'action', label: 'Block Indicator',
      desc: 'Add IP/domain/hash to firewall, proxy, or EDR block list.'
    }
  },
  {
    data: {
      id: 'act-isolate', type: 'action', label: 'Isolate Host',
      desc: 'Network-isolate the compromised endpoint to prevent lateral movement.'
    }
  },
  {
    data: {
      id: 'act-reset', type: 'action', label: 'Reset Credentials',
      desc: 'Force password reset and session invalidation for affected accounts.'
    }
  },
  {
    data: {
      id: 'act-escalate', type: 'action', label: 'Escalate Incident',
      desc: 'Open formal incident, notify IR team, preserve evidence.'
    }
  },
  {
    data: {
      id: 'act-hunt', type: 'action', label: 'Continue Hunting',
      desc: 'Expand investigation scope — pivot to related artifacts, run new hunt queries.'
    }
  }
];

const GRAPH_EDGES = [
  // ── Artifact → Enrichment ───────────────────────────────────────────
  { data: { id: 'ip-rep',       source: 'ip',      target: 'rep',       label: 'reputation' } },
  { data: { id: 'ip-asn',       source: 'ip',      target: 'asn',       label: 'geo/ASN' } },
  { data: { id: 'ip-whois',     source: 'ip',      target: 'whois',     label: 'rDNS' } },
  { data: { id: 'domain-whois', source: 'domain',  target: 'whois',     label: 'WHOIS/DNS' } },
  { data: { id: 'domain-rep',   source: 'domain',  target: 'rep',       label: 'reputation' } },
  { data: { id: 'url-rep',      source: 'url',     target: 'rep',       label: 'URL scan' } },
  { data: { id: 'hash-rep',     source: 'hash',    target: 'rep',       label: 'AV detection' } },
  { data: { id: 'hash-filemeta',source: 'hash',    target: 'file-meta', label: 'static analysis' } },
  { data: { id: 'hash-sandbox', source: 'hash',    target: 'sandbox',   label: 'dynamic analysis' } },
  { data: { id: 'proc-procmeta',source: 'process', target: 'proc-meta', label: 'process info' } },
  { data: { id: 'proc-rep',     source: 'process', target: 'rep',       label: 'hash check' } },
  { data: { id: 'email-rep',    source: 'email',   target: 'rep',       label: 'header check' } },

  // ── Enrichment → Context ────────────────────────────────────────────
  { data: { id: 'rep-titags',      source: 'rep',       target: 'ti-tags',    label: 'threat tags' } },
  { data: { id: 'rep-firstseen',   source: 'rep',       target: 'first-seen', label: 'first seen' } },
  { data: { id: 'asn-environment', source: 'asn',       target: 'environment',label: 'hosting context' } },
  { data: { id: 'whois-firstseen', source: 'whois',     target: 'first-seen', label: 'reg date' } },
  { data: { id: 'procmeta-mitre',  source: 'proc-meta', target: 'mitre',      label: 'TTP mapping' } },
  { data: { id: 'sandbox-mitre',   source: 'sandbox',   target: 'mitre',      label: 'behavior→TTP' } },
  { data: { id: 'sandbox-titags',  source: 'sandbox',   target: 'ti-tags',    label: 'malware family' } },
  { data: { id: 'filemeta-titags', source: 'file-meta', target: 'ti-tags',    label: 'family tag' } },

  // ── Artifact → Pivot ────────────────────────────────────────────────
  { data: { id: 'ip-pdomain',      source: 'ip',      target: 'p-domain',  label: 'passive DNS' } },
  { data: { id: 'ip-purl',         source: 'ip',      target: 'p-url',     label: 'hosted URLs' } },
  { data: { id: 'ip-pip',          source: 'ip',      target: 'p-ip',      label: 'same ASN' } },
  { data: { id: 'domain-pip',      source: 'domain',  target: 'p-ip',      label: 'resolved IPs' } },
  { data: { id: 'domain-purl',     source: 'domain',  target: 'p-url',     label: 'served URLs' } },
  { data: { id: 'url-pdomain',     source: 'url',     target: 'p-domain',  label: 'parent domain' } },
  { data: { id: 'url-pfile',       source: 'url',     target: 'p-file',    label: 'payload' } },
  { data: { id: 'hash-pprocess',   source: 'hash',    target: 'p-process', label: 'executed as' } },
  { data: { id: 'hash-pfile',      source: 'hash',    target: 'p-file',    label: 'dropped files' } },
  { data: { id: 'proc-pprocess',   source: 'process', target: 'p-process', label: 'child procs' } },
  { data: { id: 'proc-pfile',      source: 'process', target: 'p-file',    label: 'dropped files' } },
  { data: { id: 'proc-pip',        source: 'process', target: 'p-ip',      label: 'C2 connection' } },
  { data: { id: 'user-phost',      source: 'user',    target: 'p-host',    label: 'hosts' } },
  { data: { id: 'user-puser',      source: 'user',    target: 'p-user',    label: 'shared creds' } },
  { data: { id: 'email-purl',      source: 'email',   target: 'p-url',     label: 'embedded links' } },
  { data: { id: 'email-pfile',     source: 'email',   target: 'p-file',    label: 'attachments' } },
  { data: { id: 'email-puser',     source: 'email',   target: 'p-user',    label: 'recipients' } },
  { data: { id: 'host-pprocess',   source: 'host',    target: 'p-process', label: 'running procs' } },
  { data: { id: 'host-puser',      source: 'host',    target: 'p-user',    label: 'logged-in users' } },
  { data: { id: 'email-pip',       source: 'email',   target: 'p-ip',      label: 'header IP' } },
  { data: { id: 'host-pip',        source: 'host',    target: 'p-ip',      label: 'connections' } },
  { data: { id: 'user-pip',        source: 'user',    target: 'p-ip',      label: 'login IPs' } },
  { data: { id: 'proc-puser',      source: 'process', target: 'p-user',    label: 'process owner' } },

  // ── Cross-artifact pivoting (crossPivot: true) ──────────────────────
  { data: { id: 'ip-domain',    source: 'ip',      target: 'domain',  label: 'passive DNS',  crossPivot: true } },
  { data: { id: 'domain-url',   source: 'domain',  target: 'url',     label: 'delivery',     crossPivot: true } },
  { data: { id: 'url-hash',     source: 'url',     target: 'hash',    label: 'payload',      crossPivot: true } },
  { data: { id: 'hash-process', source: 'hash',    target: 'process', label: 'execution',    crossPivot: true } },
  { data: { id: 'process-ip',   source: 'process', target: 'ip',      label: 'C2 comm',      crossPivot: true } },
  { data: { id: 'user-host',    source: 'user',    target: 'host',    label: 'impact scope', crossPivot: true } },
  { data: { id: 'email-user',   source: 'email',   target: 'user',    label: 'entry point',  crossPivot: true } },
  { data: { id: 'url-domain',   source: 'url',     target: 'domain',  label: 'parent domain', crossPivot: true } },
  { data: { id: 'email-ip',     source: 'email',   target: 'ip',      label: 'header IP',     crossPivot: true } },
  { data: { id: 'process-hash', source: 'process', target: 'hash',    label: 'binary hash',   crossPivot: true } },
  { data: { id: 'ip-host',      source: 'ip',      target: 'host',    label: 'DHCP/asset',    crossPivot: true } },
  { data: { id: 'host-ip',      source: 'host',    target: 'ip',      label: 'connections',   crossPivot: true } },
  { data: { id: 'hash-domain',  source: 'hash',    target: 'domain',  label: 'C2 domain',     crossPivot: true } },
  { data: { id: 'hash-ip',      source: 'hash',    target: 'ip',      label: 'C2 IP',         crossPivot: true } },
  { data: { id: 'process-user', source: 'process', target: 'user',    label: 'process owner', crossPivot: true } },
  { data: { id: 'user-ip',      source: 'user',    target: 'ip',      label: 'login IPs',     crossPivot: true } },
  { data: { id: 'user-email',   source: 'user',    target: 'email',   label: 'email activity',crossPivot: true } },

  // ── Pivot → Correlation ─────────────────────────────────────────────
  { data: { id: 'pip-corrasn',       source: 'p-ip',     target: 'corr-asn',      label: '' } },
  { data: { id: 'pdomain-corrssl',   source: 'p-domain', target: 'corr-ssl',      label: '' } },
  { data: { id: 'pdomain-corrcampaign', source: 'p-domain', target: 'corr-campaign', label: '' } },
  { data: { id: 'pfile-corrmalware', source: 'p-file',   target: 'corr-malware',  label: '' } },
  { data: { id: 'titags-corrcampaign',source: 'ti-tags', target: 'corr-campaign', label: '' } },
  { data: { id: 'titags-corrmalware', source: 'ti-tags', target: 'corr-malware',  label: '' } },
  { data: { id: 'mitre-corrcampaign', source: 'mitre',   target: 'corr-campaign', label: '' } },
  { data: { id: 'firstseen-corrtime', source: 'first-seen', target: 'corr-time',  label: '' } },
  { data: { id: 'frequency-corrtime', source: 'frequency',  target: 'corr-time',  label: '' } },

  // ── Correlation + Context → Decision ────────────────────────────────
  { data: { id: 'corrcampaign-malicious', source: 'corr-campaign', target: 'dec-malicious',  label: '' } },
  { data: { id: 'corrmalware-malicious',  source: 'corr-malware',  target: 'dec-malicious',  label: '' } },
  { data: { id: 'corrasn-suspicious',     source: 'corr-asn',      target: 'dec-suspicious', label: '' } },
  { data: { id: 'corrssl-suspicious',     source: 'corr-ssl',      target: 'dec-suspicious', label: '' } },
  { data: { id: 'corrtime-suspicious',    source: 'corr-time',     target: 'dec-suspicious', label: '' } },
  { data: { id: 'rep-decmalicious',       source: 'rep',           target: 'dec-malicious',  label: 'high score' } },
  { data: { id: 'rep-decbenign',          source: 'rep',           target: 'dec-benign',     label: 'clean' } },
  { data: { id: 'rep-decunknown',         source: 'rep',           target: 'dec-unknown',    label: 'no data' } },
  { data: { id: 'environment-suspicious', source: 'environment',   target: 'dec-suspicious', label: 'anomaly' } },

  // ── Decision → Action ───────────────────────────────────────────────
  { data: { id: 'malicious-block',     source: 'dec-malicious',  target: 'act-block',    label: '' } },
  { data: { id: 'malicious-isolate',   source: 'dec-malicious',  target: 'act-isolate',  label: '' } },
  { data: { id: 'malicious-escalate',  source: 'dec-malicious',  target: 'act-escalate', label: '' } },
  { data: { id: 'suspicious-hunt',     source: 'dec-suspicious', target: 'act-hunt',     label: '' } },
  { data: { id: 'suspicious-escalate', source: 'dec-suspicious', target: 'act-escalate', label: '' } },
  { data: { id: 'benign-hunt',         source: 'dec-benign',     target: 'act-hunt',     label: 'tune & verify' } },
  { data: { id: 'unknown-hunt',        source: 'dec-unknown',    target: 'act-hunt',     label: '' } },
  { data: { id: 'malicious-reset',     source: 'dec-malicious',  target: 'act-reset',    label: 'if user involved' } }
];

const ARTIFACT_PATHS = {
  ip: {
    nodes: ['ip','rep','asn','whois','p-domain','p-url','p-ip','corr-asn','corr-campaign','first-seen','frequency','ti-tags','environment','dec-malicious','dec-suspicious','dec-benign','act-block','act-hunt','act-escalate','host'],
    label: 'IP Address',
    mitre: 'T1071 (C2), T1090 (Proxy), T1133 (External Remote Services)',
    sources: 'Firewall · NetFlow · Shodan · VT · AbuseIPDB · OTX'
  },
  domain: {
    nodes: ['domain','whois','rep','p-url','p-ip','corr-ssl','corr-campaign','first-seen','ti-tags','dec-malicious','dec-suspicious','act-block','act-hunt'],
    label: 'Domain',
    mitre: 'T1566 (Phishing), T1071.001 (Web Protocol), T1568 (Dynamic Resolution)',
    sources: 'DNS logs · WHOIS · Passive DNS · VT · OTX'
  },
  url: {
    nodes: ['url','rep','p-domain','p-file','corr-campaign','ti-tags','dec-malicious','dec-suspicious','act-block','act-hunt','domain'],
    label: 'URL',
    mitre: 'T1566.002 (Spearphishing Link), T1189 (Drive-by Compromise)',
    sources: 'Proxy logs · VT URL scan · URLscan.io · OTX'
  },
  hash: {
    nodes: ['hash','rep','file-meta','sandbox','p-process','p-file','corr-malware','ti-tags','mitre','dec-malicious','dec-suspicious','dec-benign','act-block','act-isolate','act-escalate','domain','ip'],
    label: 'File Hash',
    mitre: 'T1204 (User Execution), T1059 (Command and Scripting), T1055 (Process Injection)',
    sources: 'EDR · VT · AnyRun · MalwareBazaar · Hybrid Analysis'
  },
  process: {
    nodes: ['process','proc-meta','rep','p-process','p-file','p-ip','p-user','mitre','corr-campaign','environment','dec-malicious','dec-suspicious','act-isolate','act-hunt','act-escalate','hash','user'],
    label: 'Process',
    mitre: 'T1059 (Execution), T1055 (Injection), T1003 (Cred Dump), T1021 (Lateral Move)',
    sources: 'EDR · Sysmon · Windows Event 4688 · Process tree'
  },
  user: {
    nodes: ['user','p-host','p-user','p-ip','corr-time','environment','frequency','dec-suspicious','dec-malicious','act-reset','act-escalate','act-hunt','ip','email'],
    label: 'User',
    mitre: 'T1078 (Valid Accounts), T1021 (Lateral Movement), T1098 (Account Manipulation)',
    sources: 'AD · IAM · Okta · SIEM UEBA · Windows Security logs'
  },
  email: {
    nodes: ['email','rep','p-url','p-file','p-user','p-ip','corr-campaign','ti-tags','dec-malicious','dec-suspicious','act-block','act-hunt','act-escalate','ip'],
    label: 'Email',
    mitre: 'T1566 (Phishing), T1598 (Spearphishing for Info), T1534 (Internal Spearphishing)',
    sources: 'Email Gateway · O365 Message Trace · SIEM · Header analysis'
  },
  host: {
    nodes: ['host','p-process','p-user','p-ip','environment','corr-time','frequency','mitre','dec-suspicious','dec-malicious','act-isolate','act-hunt','act-escalate','ip'],
    label: 'Host',
    mitre: 'T1005 (Data from Local System), T1021 (Lateral Movement), T1070 (Indicator Removal)',
    sources: 'EDR · SIEM · AD · Vulnerability Scanner · CMDB'
  }
};
