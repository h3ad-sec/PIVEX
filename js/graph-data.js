// PIVEX — graph-data.js  v9.3
// 30 artifact nodes + directed edges from pivots.json

const GRAPH_NODES = [
  // ── ARTIFACT NODES — Network (12) ────────────────────────────────────────
  { data: { id: 'ip', type: 'artifact', category: 'network', label: 'IP Address',
      desc: 'IPv4/IPv6 address observed in logs, alerts, or network telemetry.',
      sources: 'Firewall · SIEM · NetFlow · Proxy · EDR',
      pivots: ['Domain (resolves_to)', 'FQDN (resolves_to)', 'URL (hosts)', 'Network Session (communicates_with)', 'SSL Certificate (presents)', 'Network Traffic (observed_in)'],
      mitre: 'T1071.001 · T1090 · T1046 · T1016' }},
  { data: { id: 'domain', type: 'artifact', category: 'network', label: 'Domain',
      desc: 'Domain name seen in DNS queries, HTTP traffic, or email headers.',
      sources: 'DNS logs · Proxy · Email Gateway · Passive DNS',
      pivots: ['IP (resolves_to)', 'FQDN (parent_of)', 'URL (hosts)', 'SSL Certificate (uses)', 'Email (used_in)'],
      mitre: 'T1071 · T1566.002 · T1190 · T1584.001' }},
  { data: { id: 'fqdn', type: 'artifact', category: 'network', label: 'FQDN',
      desc: 'Fully qualified domain name — precise subdomain used in C2 or delivery.',
      sources: 'DNS logs · Proxy · EDR · Sysmon Event 22',
      pivots: ['Domain (belongs_to)', 'IP (resolves_to)', 'URL (hosts)'],
      mitre: 'T1071 · T1568' }},
  { data: { id: 'url', type: 'artifact', category: 'network', label: 'URL',
      desc: 'Full URL from proxy, email links, or browser history.',
      sources: 'Proxy logs · Email Gateway · Browser history · EDR',
      pivots: ['Domain (belongs_to)', 'FQDN (belongs_to)', 'IP (connects_to)', 'HTTP Request (requested_via)', 'File (delivers)', 'User Agent (accessed_by)', 'Email (embedded_in)'],
      mitre: 'T1566.002 · T1204.001 · T1071.001' }},
  { data: { id: 'dns_query', type: 'artifact', category: 'network', label: 'DNS Query',
      desc: 'DNS resolution request — reveals C2 beaconing, DGA, and exfil patterns.',
      sources: 'DNS logs · Sysmon Event 22 · EDR · Network tap',
      pivots: ['Domain (queries)', 'IP (resolves_to)', 'Host (initiated_by)'],
      mitre: 'T1071.004 · T1568 · T1048.003' }},
  { data: { id: 'http_request', type: 'artifact', category: 'network', label: 'HTTP Request',
      desc: 'HTTP/S request with method, headers, user-agent, and response.',
      sources: 'Proxy · Firewall · EDR · Zeek / Suricata · Network sensor',
      pivots: ['URL (targets)', 'User Agent (uses)'],
      mitre: 'T1071.001 · T1105 · T1041' }},
  { data: { id: 'ssl_cert', type: 'artifact', category: 'network', label: 'SSL Cert',
      desc: 'SSL/TLS certificate reference — shorthand mapping to a certificate record.',
      sources: 'Censys · Shodan · crt.sh · JARM · Passive DNS',
      pivots: [],
      mitre: 'T1553.004 · T1584' }},
  { data: { id: 'ssl_certificate', type: 'artifact', category: 'network', label: 'SSL Certificate',
      desc: 'Full SSL/TLS certificate — serial, CN, SAN — strong infrastructure clustering.',
      sources: 'Censys · Shodan · crt.sh · JARM · Passive DNS',
      pivots: ['Domain (issued_to)', 'IP (used_by)'],
      mitre: 'T1553.004 · T1584 · T1090.002' }},
  { data: { id: 'ja3', type: 'artifact', category: 'network', label: 'JA3 Hash',
      desc: 'TLS client fingerprint — identifies malware TLS implementation uniquely.',
      sources: 'Network sensor · Zeek · Suricata · PCAP',
      pivots: ['IP (observed_on)', 'Domain (connects_to)'],
      mitre: 'T1071.001 · T1573' }},
  { data: { id: 'user_agent', type: 'artifact', category: 'network', label: 'User Agent',
      desc: 'HTTP User-Agent string — identifies tool, framework, or spoofed browser.',
      sources: 'Proxy · Zeek · Firewall · SIEM',
      pivots: ['URL (accesses)', 'IP (observed_from)', 'Network Session (part_of)'],
      mitre: 'T1071.001 · T1218' }},
  { data: { id: 'network_traffic', type: 'artifact', category: 'network', label: 'Net Traffic',
      desc: 'NetFlow/PCAP session record — port, protocol, volume, and timing metadata.',
      sources: 'NetFlow · Zeek · Suricata · PCAP · Firewall · Network sensor',
      pivots: ['IP (involves)'],
      mitre: 'T1040 · T1046 · T1071' }},
  { data: { id: 'network_session', type: 'artifact', category: 'network', label: 'Net Session',
      desc: 'Network session — source/destination IPs, domain contacted, URL accessed.',
      sources: 'NetFlow · Firewall · Proxy · Zeek · EDR',
      pivots: ['IP (originates_from / connects_to)', 'Domain (queries)', 'URL (accesses)'],
      mitre: 'T1071.001 · T1071.004 · T1048' }},

  // ── ARTIFACT NODES — Endpoint (12) ───────────────────────────────────────
  { data: { id: 'hash', type: 'artifact', category: 'endpoint', label: 'File Hash',
      desc: 'MD5/SHA1/SHA256 of a file on disk, in memory, or from email attachment.',
      sources: 'EDR · AV · Sandbox · MalwareBazaar · Email scan',
      pivots: ['File (identifies)', 'URL (downloaded_from)', 'IP (hosted_on)', 'Domain (associated_with)', 'Process (executed_by)'],
      mitre: 'T1027 · T1064 · T1204.002 · T1059' }},
  { data: { id: 'file', type: 'artifact', category: 'endpoint', label: 'File',
      desc: 'Binary, script, document, or any on-disk file artifact.',
      sources: 'EDR · Sandbox · AV · MalwareBazaar · File system audit',
      pivots: ['Hash (has_hash)', 'Process (executed_by / spawned_by)', 'Host (exists_on)', 'User (owned_by)'],
      mitre: 'T1027 · T1204.002 · T1059 · T1083' }},
  { data: { id: 'file_path', type: 'artifact', category: 'endpoint', label: 'File Path',
      desc: 'File / directory path — drop locations, staging dirs, LOLBin paths.',
      sources: 'EDR · Sysmon Event 11 · Windows Security · MFT · USN Journal',
      pivots: ['File (points_to)'],
      mitre: 'T1074 · T1083 · T1036.005' }},
  { data: { id: 'process', type: 'artifact', category: 'endpoint', label: 'Process',
      desc: 'Running or historical process — command line, spawns, registry writes, and network activity.',
      sources: 'EDR · Sysmon Event 1 · WinEvent 4688 · Process Monitor',
      pivots: ['Registry (modifies)', 'Scheduled Task (creates)', 'Startup Item (creates)', 'Process (spawned_by / spawns)', 'Command Line (executed_with)', 'File (runs)', 'User (executed_as)', 'Host (runs_on)'],
      mitre: 'T1059 · T1055 · T1003 · T1218 · T1071' }},
  { data: { id: 'command_line', type: 'artifact', category: 'endpoint', label: 'Command Line',
      desc: 'Full command-line string — LOLBin abuse, encoded payloads, script execution.',
      sources: 'EDR · Sysmon Event 1 · WinEvent 4688 · PowerShell logs · ScriptBlock',
      pivots: ['Process (used_by)'],
      mitre: 'T1059 · T1027.010 · T1218' }},
  { data: { id: 'registry', type: 'artifact', category: 'endpoint', label: 'Registry Key',
      desc: 'Windows registry key/value — persistence, configuration, and malware indicators.',
      sources: 'Sysmon 12/13/14 · EDR · WinEvent 4657 · Autoruns · reg.exe',
      pivots: ['Host (exists_on)'],
      mitre: 'T1547.001 · T1112' }},
  { data: { id: 'scheduled_task', type: 'artifact', category: 'endpoint', label: 'Sched. Task',
      desc: 'Windows scheduled task — persistence and lateral execution mechanism.',
      sources: 'Sysmon Event 11 · EDR · Task Scheduler logs · WinEvent 4698',
      pivots: ['Host (runs_on)'],
      mitre: 'T1053.005 · T1053' }},
  { data: { id: 'startup_item', type: 'artifact', category: 'endpoint', label: 'Startup Item',
      desc: 'Startup folder, run key, or IFEO entry — persistent execution after reboot.',
      sources: 'Autoruns · EDR · Sysmon · Registry audit · WinEvent 4688',
      pivots: ['Host (runs_on)'],
      mitre: 'T1547 · T1037' }},
  { data: { id: 'host', type: 'artifact', category: 'endpoint', label: 'Host',
      desc: 'Endpoint, server, or workstation involved in the incident.',
      sources: 'EDR · SIEM · AD · Vuln Scanner · CMDB',
      pivots: ['Process (runs)', 'File (stores)', 'User (used_by)', 'IP (assigned)', 'Network Session (generates)'],
      mitre: 'T1018 · T1082 · T1016' }},
  { data: { id: 'share', type: 'artifact', category: 'endpoint', label: 'Network Share',
      desc: 'SMB/NFS share — lateral movement staging, data collection, exfil path.',
      sources: 'WinEvent 5140/5145 · EDR · Sysmon · Network traffic · AD',
      pivots: ['Host (hosted_on)'],
      mitre: 'T1021.002 · T1039 · T1074' }},
  { data: { id: 'event_id', type: 'artifact', category: 'endpoint', label: 'Event ID',
      desc: 'Windows Event ID — specific log event correlating process, user, or host.',
      sources: 'Windows Event Log · SIEM · Splunk · Elastic',
      pivots: ['Process (relates_to)'],
      mitre: 'T1562.002 · T1070.001' }},
  { data: { id: 'vulnerability_id', type: 'artifact', category: 'endpoint', label: 'Vuln ID',
      desc: 'CVE / vulnerability identifier — links exploit activity to host.',
      sources: 'NVD · CISA KEV · Tenable · Qualys · Shodan · EDR',
      pivots: ['Host (affects)'],
      mitre: 'T1190 · T1068 · T1203' }},

  // ── ARTIFACT NODES — Identity (3) ────────────────────────────────────────
  { data: { id: 'user', type: 'artifact', category: 'identity', label: 'User',
      desc: 'User account — local, domain, or service account involved in the activity.',
      sources: 'AD logs · IAM · Okta · SIEM · UEBA',
      pivots: ['Host (logs_into)', 'Process (executes)', 'IP (originates_from)', 'Cloud Resource (accesses)'],
      mitre: 'T1078 · T1087 · T1021' }},
  { data: { id: 'identity', type: 'artifact', category: 'identity', label: 'Identity',
      desc: 'Cloud / federated identity — Azure AD, AWS IAM, GCP SA — cloud access vector.',
      sources: 'Azure AD · AWS IAM · GCP SA · Okta · SIEM · CloudTrail',
      pivots: ['User (represents)'],
      mitre: 'T1078.004 · T1136.003 · T1098' }},
  { data: { id: 'rdp_session', type: 'artifact', category: 'identity', label: 'RDP Session',
      desc: 'RDP session — lateral movement, credential exposure, remote access.',
      sources: 'WinEvent 4624/4778/4779 · EDR · NetFlow · Security Onion',
      pivots: ['Host (connects_to)', 'User (initiated_by)'],
      mitre: 'T1021.001 · T1563.002' }},

  // ── ARTIFACT NODES — Email (2) ────────────────────────────────────────────
  { data: { id: 'email', type: 'artifact', category: 'email', label: 'Email',
      desc: 'Phishing or suspicious email — headers, body, embedded URLs, attachments.',
      sources: 'Email Gateway · O365 Message Trace · SIEM · Proofpoint · Mimecast',
      pivots: ['Attachment (contains)', 'URL (contains)', 'Domain (originates_from)'],
      mitre: 'T1566.001 · T1566.002 · T1598' }},
  { data: { id: 'attachment', type: 'artifact', category: 'email', label: 'Attachment',
      desc: 'Email attachment — document with macro, PE dropper, or archive payload.',
      sources: 'Email Gateway · Sandbox · AV · EDR · O365 ATP',
      pivots: ['Hash (has_hash)'],
      mitre: 'T1566.001 · T1204.002 · T1027' }},

  // ── ARTIFACT NODES — Cloud (1) ────────────────────────────────────────────
  { data: { id: 'cloud_resource', type: 'artifact', category: 'cloud', label: 'Cloud Resource',
      desc: 'S3 bucket, Azure blob, IAM role, Lambda, or cloud compute resource.',
      sources: 'CloudTrail · Azure Monitor · GCP Audit · GuardDuty · Defender for Cloud',
      pivots: ['Identity (owned_by)', 'IP (exposed_via)'],
      mitre: 'T1078.004 · T1537 · T1530 · T1619' }}
];

const GRAPH_EDGES = [
  // ── Edges from pivots.json (artifact-to-artifact, directed) ──────────────

  // IP
  { data: { id: 'ip-domain',              source: 'ip',    target: 'domain',           crossPivot: true, label: 'resolves_to' }},
  { data: { id: 'ip-fqdn',                source: 'ip',    target: 'fqdn',             crossPivot: true, label: 'resolves_to' }},
  { data: { id: 'ip-url',                 source: 'ip',    target: 'url',              crossPivot: true, label: 'hosts' }},
  { data: { id: 'ip-network_session',     source: 'ip',    target: 'network_session',  crossPivot: true, label: 'communicates_with' }},
  { data: { id: 'ip-ssl_certificate',     source: 'ip',    target: 'ssl_certificate',  crossPivot: true, label: 'presents' }},
  { data: { id: 'ip-network_traffic',     source: 'ip',    target: 'network_traffic',  crossPivot: true, label: 'observed_in' }},

  // Domain
  { data: { id: 'domain-ip',              source: 'domain', target: 'ip',              crossPivot: true, label: 'resolves_to' }},
  { data: { id: 'domain-fqdn',            source: 'domain', target: 'fqdn',            crossPivot: true, label: 'parent_of' }},
  { data: { id: 'domain-url',             source: 'domain', target: 'url',             crossPivot: true, label: 'hosts' }},
  { data: { id: 'domain-sslcertificate',  source: 'domain', target: 'ssl_certificate', crossPivot: true, label: 'uses' }},
  { data: { id: 'domain-email',           source: 'domain', target: 'email',           crossPivot: true, label: 'used_in' }},

  // FQDN
  { data: { id: 'fqdn-domain',            source: 'fqdn', target: 'domain',            crossPivot: true, label: 'belongs_to' }},
  { data: { id: 'fqdn-ip',                source: 'fqdn', target: 'ip',                crossPivot: true, label: 'resolves_to' }},
  { data: { id: 'fqdn-url',               source: 'fqdn', target: 'url',               crossPivot: true, label: 'hosts' }},

  // URL
  { data: { id: 'url-domain',             source: 'url', target: 'domain',             crossPivot: true, label: 'belongs_to' }},
  { data: { id: 'url-fqdn',               source: 'url', target: 'fqdn',               crossPivot: true, label: 'belongs_to' }},
  { data: { id: 'url-ip',                 source: 'url', target: 'ip',                 crossPivot: true, label: 'connects_to' }},
  { data: { id: 'url-http_request',       source: 'url', target: 'http_request',       crossPivot: true, label: 'requested_via' }},
  { data: { id: 'url-file',               source: 'url', target: 'file',               crossPivot: true, label: 'delivers' }},
  { data: { id: 'url-user_agent',         source: 'url', target: 'user_agent',         crossPivot: true, label: 'accessed_by' }},
  { data: { id: 'url-email',              source: 'url', target: 'email',              crossPivot: true, label: 'embedded_in' }},

  // Hash
  { data: { id: 'hash-file',              source: 'hash', target: 'file',              crossPivot: true, label: 'identifies' }},
  { data: { id: 'hash-url',               source: 'hash', target: 'url',               crossPivot: true, label: 'downloaded_from' }},
  { data: { id: 'hash-ip',                source: 'hash', target: 'ip',                crossPivot: true, label: 'hosted_on' }},
  { data: { id: 'hash-domain',            source: 'hash', target: 'domain',            crossPivot: true, label: 'associated_with' }},
  { data: { id: 'hash-process',           source: 'hash', target: 'process',           crossPivot: true, label: 'executed_by' }},

  // DNS Query
  { data: { id: 'dnsq-domain',            source: 'dns_query', target: 'domain',       crossPivot: true, label: 'queries' }},
  { data: { id: 'dnsq-ip',                source: 'dns_query', target: 'ip',           crossPivot: true, label: 'resolves_to' }},
  { data: { id: 'dnsq-host',              source: 'dns_query', target: 'host',         crossPivot: true, label: 'initiated_by' }},

  // File
  { data: { id: 'file-hash',              source: 'file', target: 'hash',              crossPivot: true, label: 'has_hash' }},
  { data: { id: 'file-process-exec',      source: 'file', target: 'process',           crossPivot: true, label: 'executed_by' }},
  { data: { id: 'file-process-spawn',     source: 'file', target: 'process',           crossPivot: true, label: 'spawned_by' }},
  { data: { id: 'file-host',              source: 'file', target: 'host',              crossPivot: true, label: 'exists_on' }},
  { data: { id: 'file-user',              source: 'file', target: 'user',              crossPivot: true, label: 'owned_by' }},

  // HTTP Request
  { data: { id: 'httpreq-url',            source: 'http_request', target: 'url',       crossPivot: true, label: 'targets' }},
  { data: { id: 'httpreq-ua',             source: 'http_request', target: 'user_agent',crossPivot: true, label: 'uses' }},

  // File Path
  { data: { id: 'filepath-file',          source: 'file_path', target: 'file',         crossPivot: true, label: 'points_to' }},

  // Process
  { data: { id: 'proc-registry',          source: 'process', target: 'registry',       crossPivot: true, label: 'modifies' }},
  { data: { id: 'proc-scheduled_task',    source: 'process', target: 'scheduled_task', crossPivot: true, label: 'creates' }},
  { data: { id: 'proc-startup_item',      source: 'process', target: 'startup_item',   crossPivot: true, label: 'creates' }},
  { data: { id: 'proc-proc-spawned',      source: 'process', target: 'process',        crossPivot: true, label: 'spawned_by' }},
  { data: { id: 'proc-proc-spawns',       source: 'process', target: 'process',        crossPivot: true, label: 'spawns' }},
  { data: { id: 'proc-command_line',      source: 'process', target: 'command_line',   crossPivot: true, label: 'executed_with' }},
  { data: { id: 'proc-file',              source: 'process', target: 'file',           crossPivot: true, label: 'runs' }},
  { data: { id: 'proc-user',              source: 'process', target: 'user',           crossPivot: true, label: 'executed_as' }},
  { data: { id: 'proc-host',              source: 'process', target: 'host',           crossPivot: true, label: 'runs_on' }},

  // User
  { data: { id: 'user-host',              source: 'user', target: 'host',              crossPivot: true, label: 'logs_into' }},
  { data: { id: 'user-process',           source: 'user', target: 'process',           crossPivot: true, label: 'executes' }},
  { data: { id: 'user-ip',                source: 'user', target: 'ip',                crossPivot: true, label: 'originates_from' }},
  { data: { id: 'user-cloud_resource',    source: 'user', target: 'cloud_resource',    crossPivot: true, label: 'accesses' }},

  // Host
  { data: { id: 'host-process',           source: 'host', target: 'process',           crossPivot: true, label: 'runs' }},
  { data: { id: 'host-file',              source: 'host', target: 'file',              crossPivot: true, label: 'stores' }},
  { data: { id: 'host-user',              source: 'host', target: 'user',              crossPivot: true, label: 'used_by' }},
  { data: { id: 'host-ip',                source: 'host', target: 'ip',                crossPivot: true, label: 'assigned' }},
  { data: { id: 'host-network_session',   source: 'host', target: 'network_session',   crossPivot: true, label: 'generates' }},

  // Network Session
  { data: { id: 'netsess-ip-from',        source: 'network_session', target: 'ip',     crossPivot: true, label: 'originates_from' }},
  { data: { id: 'netsess-ip-to',          source: 'network_session', target: 'ip',     crossPivot: true, label: 'connects_to' }},
  { data: { id: 'netsess-domain',         source: 'network_session', target: 'domain', crossPivot: true, label: 'queries' }},
  { data: { id: 'netsess-url',            source: 'network_session', target: 'url',    crossPivot: true, label: 'accesses' }},

  // SSL Certificate
  { data: { id: 'sslcert-domain',         source: 'ssl_certificate', target: 'domain', crossPivot: true, label: 'issued_to' }},
  { data: { id: 'sslcert-ip',             source: 'ssl_certificate', target: 'ip',     crossPivot: true, label: 'used_by' }},

  // Cloud Resource
  { data: { id: 'cloud-identity',         source: 'cloud_resource', target: 'identity',crossPivot: true, label: 'owned_by' }},
  { data: { id: 'cloud-ip',               source: 'cloud_resource', target: 'ip',      crossPivot: true, label: 'exposed_via' }},

  // JA3
  { data: { id: 'ja3-ip',                 source: 'ja3', target: 'ip',                 crossPivot: true, label: 'observed_on' }},
  { data: { id: 'ja3-domain',             source: 'ja3', target: 'domain',             crossPivot: true, label: 'connects_to' }},

  // User Agent
  { data: { id: 'ua-url',                 source: 'user_agent', target: 'url',         crossPivot: true, label: 'accesses' }},
  { data: { id: 'ua-ip',                  source: 'user_agent', target: 'ip',          crossPivot: true, label: 'observed_from' }},
  { data: { id: 'ua-network_session',     source: 'user_agent', target: 'network_session',crossPivot: true, label: 'part_of' }},

  // Email
  { data: { id: 'email-attachment',       source: 'email', target: 'attachment',       crossPivot: true, label: 'contains' }},
  { data: { id: 'email-url',              source: 'email', target: 'url',              crossPivot: true, label: 'contains' }},
  { data: { id: 'email-domain',           source: 'email', target: 'domain',           crossPivot: true, label: 'originates_from' }},

  // Attachment
  { data: { id: 'attach-hash',            source: 'attachment', target: 'hash',        crossPivot: true, label: 'has_hash' }},

  // Registry
  { data: { id: 'reg-host',               source: 'registry', target: 'host',          crossPivot: true, label: 'exists_on' }},

  // Scheduled Task
  { data: { id: 'task-host',              source: 'scheduled_task', target: 'host',    crossPivot: true, label: 'runs_on' }},

  // Startup Item
  { data: { id: 'startup-host',           source: 'startup_item', target: 'host',      crossPivot: true, label: 'runs_on' }},

  // Share
  { data: { id: 'share-host',             source: 'share', target: 'host',             crossPivot: true, label: 'hosted_on' }},

  // RDP Session
  { data: { id: 'rdp-host',               source: 'rdp_session', target: 'host',       crossPivot: true, label: 'connects_to' }},
  { data: { id: 'rdp-user',               source: 'rdp_session', target: 'user',       crossPivot: true, label: 'initiated_by' }},

  // Event ID
  { data: { id: 'evtid-process',          source: 'event_id', target: 'process',       crossPivot: true, label: 'relates_to' }},

  // Command Line
  { data: { id: 'cmdline-process',        source: 'command_line', target: 'process',   crossPivot: true, label: 'used_by' }},

  // Vulnerability ID
  { data: { id: 'vuln-host',              source: 'vulnerability_id', target: 'host',  crossPivot: true, label: 'affects' }},

  // Network Traffic
  { data: { id: 'nettraffic-ip',          source: 'network_traffic', target: 'ip',     crossPivot: true, label: 'involves' }},

  // Identity
  { data: { id: 'identity-user',          source: 'identity', target: 'user',          crossPivot: true, label: 'represents' }}
];

// ── ARTIFACT_PATHS — programmatic from GRAPH_EDGES ────────────────────────
const ARTIFACT_PATHS = {};
(function () {
  var MITRE_INFO = {
    ip:               'T1071.001 · T1090 · T1046 · T1016',
    domain:           'T1071 · T1566.002 · T1190 · T1584.001',
    fqdn:             'T1071 · T1568',
    url:              'T1566.002 · T1204.001 · T1071.001',
    dns_query:        'T1071.004 · T1568 · T1048.003',
    http_request:     'T1071.001 · T1105 · T1041',
    ssl_cert:         'T1553.004 · T1584',
    ssl_certificate:  'T1553.004 · T1584 · T1090.002',
    ja3:              'T1071.001 · T1573',
    user_agent:       'T1071.001 · T1218',
    network_traffic:  'T1040 · T1046 · T1071',
    network_session:  'T1071.001 · T1071.004 · T1048',
    hash:             'T1027 · T1064 · T1204.002 · T1059',
    file:             'T1027 · T1204.002 · T1059 · T1083',
    file_path:        'T1074 · T1083 · T1036.005',
    process:          'T1059 · T1055 · T1003 · T1218 · T1071',
    command_line:     'T1059 · T1027.010 · T1218',
    registry:         'T1547.001 · T1112',
    scheduled_task:   'T1053.005 · T1053',
    startup_item:     'T1547 · T1037',
    host:             'T1018 · T1082 · T1016',
    share:            'T1021.002 · T1039 · T1074',
    event_id:         'T1562.002 · T1070.001',
    vulnerability_id: 'T1190 · T1068 · T1203',
    user:             'T1078 · T1087 · T1021',
    identity:         'T1078.004 · T1136.003 · T1098',
    rdp_session:      'T1021.001 · T1563.002',
    email:            'T1566.001 · T1566.002 · T1598',
    attachment:       'T1566.001 · T1204.002 · T1027',
    cloud_resource:   'T1078.004 · T1537 · T1530 · T1619'
  };
  var nbrs = {};
  GRAPH_NODES.forEach(function (n) {
    if (n.data.type === 'artifact') nbrs[n.data.id] = new Set([n.data.id]);
  });
  GRAPH_EDGES.forEach(function (e) {
    var s = e.data.source, t = e.data.target;
    if (nbrs[s]) nbrs[s].add(t);
    if (nbrs[t]) nbrs[t].add(s);
  });
  GRAPH_NODES.forEach(function (n) {
    if (n.data.type !== 'artifact') return;
    var id = n.data.id;
    ARTIFACT_PATHS[id] = {
      label: n.data.label,
      nodes: Array.from(nbrs[id]),
      mitre: MITRE_INFO[id] || 'See MITRE ATT&CK',
      sources: n.data.sources
    };
  });
}());
