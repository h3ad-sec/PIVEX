// PIVEX — graph-data.js  v8.3
// H3AD-PIVEX spec: 37 artifacts, pivot_map edges, programmatic ARTIFACT_PATHS

const GRAPH_NODES = [
  // ── ARTIFACT NODES — Network ──────────────────────────────────────────
  { data: { id: 'ip', type: 'artifact', category: 'network', label: 'IP Address',
      desc: 'IPv4/IPv6 address observed in logs, alerts, or network telemetry.',
      sources: 'Firewall · SIEM · NetFlow · Proxy · EDR',
      pivots: ['Passive DNS → Domain', 'FQDN resolution', 'ASN / hosting', 'Open ports', 'Hosted services', 'SSL cert presented'],
      mitre: 'T1071.001 · T1090 · T1046 · T1016' }},
  { data: { id: 'domain', type: 'artifact', category: 'network', label: 'Domain',
      desc: 'Domain name seen in DNS queries, HTTP traffic, or email headers.',
      sources: 'DNS logs · Proxy · Email Gateway · Passive DNS',
      pivots: ['Resolved IPs', 'FQDNs on domain', 'DNS records', 'SSL cert used'],
      mitre: 'T1071 · T1566.002 · T1190 · T1584.001' }},
  { data: { id: 'fqdn', type: 'artifact', category: 'network', label: 'FQDN',
      desc: 'Fully qualified domain name — precise subdomain used in C2 or delivery.',
      sources: 'DNS logs · Proxy · EDR · Sysmon Event 22',
      pivots: ['Resolved IP', 'Parent domain'],
      mitre: 'T1071 · T1568' }},
  { data: { id: 'url', type: 'artifact', category: 'network', label: 'URL',
      desc: 'Full URL from proxy, email links, or browser history.',
      sources: 'Proxy logs · Email Gateway · Browser history · EDR',
      pivots: ['Parent domain', 'Hosting IP', 'Downloaded payload (→ Hash)', 'HTTP request details'],
      mitre: 'T1566.002 · T1204.001 · T1071.001' }},
  { data: { id: 'dns_query', type: 'artifact', category: 'network', label: 'DNS Query',
      desc: 'DNS resolution request — reveals C2 beaconing, DGA, and exfil patterns.',
      sources: 'DNS logs · Sysmon Event 22 · EDR · Network tap',
      pivots: ['Queried domain', 'Queried FQDN', 'Process that initiated it'],
      mitre: 'T1071.004 · T1568 · T1048.003' }},
  { data: { id: 'http_request', type: 'artifact', category: 'network', label: 'HTTP Request',
      desc: 'HTTP/S request with method, headers, user-agent, and response.',
      sources: 'Proxy · Firewall · EDR · Zeek / Suricata · Network sensor',
      pivots: ['Target URL', 'User-Agent string', 'Process that initiated it'],
      mitre: 'T1071.001 · T1105 · T1041' }},
  { data: { id: 'asn', type: 'artifact', category: 'network', label: 'ASN',
      desc: 'Autonomous System Number — identifies hosting provider, CDN, or proxy infra.',
      sources: 'Shodan · BGP data · IPinfo · MaxMind · RIPE',
      pivots: ['IPs in this ASN', 'Geo / org context'],
      mitre: 'T1090 · T1584.003' }},
  { data: { id: 'dns_record', type: 'artifact', category: 'network', label: 'DNS Record',
      desc: 'A/AAAA/MX/NS/TXT/CNAME — pivots from domain to IP infrastructure.',
      sources: 'WHOIS · Passive DNS · RiskIQ · Farsight · SecurityTrails',
      pivots: ['Resolved IP address'],
      mitre: 'T1584.001 · T1071.004' }},
  { data: { id: 'ssl_cert', type: 'artifact', category: 'network', label: 'SSL Cert',
      desc: 'SSL/TLS certificate — serial, CN, SAN — strong infrastructure clustering.',
      sources: 'Censys · Shodan · crt.sh · Passive DNS · JARM',
      pivots: ['Domain it was issued to', 'IPs where it was observed'],
      mitre: 'T1553.004 · T1584 · T1090.002' }},
  { data: { id: 'ja3', type: 'artifact', category: 'network', label: 'JA3 Hash',
      desc: 'TLS client fingerprint — identifies malware TLS implementation uniquely.',
      sources: 'Network sensor · Zeek · Suricata · PCAP',
      pivots: ['Source IP using this fingerprint'],
      mitre: 'T1071.001 · T1573' }},
  { data: { id: 'user_agent', type: 'artifact', category: 'network', label: 'User Agent',
      desc: 'HTTP User-Agent string — identifies tool, framework, or spoofed browser.',
      sources: 'Proxy · Zeek · Firewall · SIEM',
      pivots: ['HTTP requests using this UA', 'Tool / malware family'],
      mitre: 'T1071.001 · T1218' }},
  { data: { id: 'port', type: 'artifact', category: 'network', label: 'Port',
      desc: 'Network port — anomalous service port indicating C2, pivot, or scanning.',
      sources: 'Firewall logs · Shodan · EDR · Nmap · Masscan',
      pivots: ['Service running on port', 'IP exposing this port'],
      mitre: 'T1046 · T1571' }},
  { data: { id: 'certificate', type: 'artifact', category: 'network', label: 'Code-Sign Cert',
      desc: 'Code-signing certificate — authenticates binary or indicates stolen signing.',
      sources: 'VT code-signing · Censys · VirusTotal · PE analysis',
      pivots: ['Signed binary (→ Hash)', 'Certificate issuer'],
      mitre: 'T1553.002 · T1036.001' }},

  // ── ARTIFACT NODES — Endpoint ─────────────────────────────────────────
  { data: { id: 'hash', type: 'artifact', category: 'endpoint', label: 'File Hash',
      desc: 'MD5/SHA1/SHA256 of a file on disk, in memory, or from email attachment.',
      sources: 'EDR · AV · Sandbox · MalwareBazaar · Email scan',
      pivots: ['Executed process', 'File path on disk', 'C2 domain / IP contacted', 'Malware family'],
      mitre: 'T1027 · T1064 · T1204.002 · T1059' }},
  { data: { id: 'file_path', type: 'artifact', category: 'endpoint', label: 'File Path',
      desc: 'File / directory path — drop locations, staging dirs, LOLBin paths.',
      sources: 'EDR · Sysmon Event 11 · Windows Security · MFT · USN Journal',
      pivots: ['Process spawned from this path', 'Hash at this path'],
      mitre: 'T1074 · T1083 · T1036.005' }},
  { data: { id: 'process', type: 'artifact', category: 'endpoint', label: 'Process',
      desc: 'Running or historical process — command line, parent, hash, and network activity.',
      sources: 'EDR · Sysmon Event 1 · WinEvent 4688 · Process Monitor',
      pivots: ['Binary hash', 'Execution path', 'C2 IP / domain', 'Host', 'User context', 'Registry writes', 'Scheduled tasks', 'Services', 'Mutex', 'Named pipe', 'Driver / DLL loads', 'DNS queries', 'HTTP requests'],
      mitre: 'T1059 · T1055 · T1003 · T1218 · T1071' }},
  { data: { id: 'process_guid', type: 'artifact', category: 'endpoint', label: 'Process GUID',
      desc: 'Unique Sysmon process GUID — correlates process events across machines and time.',
      sources: 'Sysmon · EDR · Windows Event Logs',
      pivots: ['Associated process', 'Host context'],
      mitre: 'T1057' }},
  { data: { id: 'dll', type: 'artifact', category: 'endpoint', label: 'DLL',
      desc: 'DLL — hijacking, sideloading, or reflective injection indicator.',
      sources: 'EDR · Sysmon Event 7 · Process Monitor · PE analysis · VT',
      pivots: ['Hash of DLL', 'Process that loaded it', 'File path'],
      mitre: 'T1574.001 · T1574.002 · T1129' }},
  { data: { id: 'driver', type: 'artifact', category: 'endpoint', label: 'Driver',
      desc: 'Kernel driver load — rootkits, bootkits, or BYOD attacks.',
      sources: 'Sysmon Event 6 · EDR · WinEvent 7045 · DriverQuery · WinPmem',
      pivots: ['Driver hash', 'Process that loaded it'],
      mitre: 'T1014 · T1547.006 · T1068' }},
  { data: { id: 'service', type: 'artifact', category: 'endpoint', label: 'Service',
      desc: 'Windows service — malicious installs, driver loads, privilege escalation.',
      sources: 'Sysmon Event 6 · EDR · WinEvent 7045 · sc.exe · Services registry',
      pivots: ['Port it listens on', 'Host where running', 'SPN representing it', 'Kerberos access'],
      mitre: 'T1543.003 · T1050 · T1021.002' }},
  { data: { id: 'registry', type: 'artifact', category: 'endpoint', label: 'Registry Key',
      desc: 'Windows registry key/value — persistence, configuration, and malware indicators.',
      sources: 'Sysmon 12/13/14 · EDR · WinEvent 4657 · Autoruns · reg.exe',
      pivots: ['Process that modified it', 'Service defined by key'],
      mitre: 'T1547.001 · T1112' }},
  { data: { id: 'scheduled_task', type: 'artifact', category: 'endpoint', label: 'Sched. Task',
      desc: 'Windows scheduled task — persistence and lateral execution mechanism.',
      sources: 'Sysmon Event 11 · EDR · Task Scheduler logs',
      pivots: ['Process it spawns', 'User who created it'],
      mitre: 'T1053.005 · T1053' }},
  { data: { id: 'startup_item', type: 'artifact', category: 'endpoint', label: 'Startup Item',
      desc: 'Startup folder, run key, or IFEO entry — persistent execution after reboot.',
      sources: 'Autoruns · EDR · Sysmon · Registry audit · WinEvent 4688',
      pivots: ['Process executed on startup', 'Registry key backing it'],
      mitre: 'T1547 · T1037' }},
  { data: { id: 'mutex', type: 'artifact', category: 'endpoint', label: 'Mutex',
      desc: 'Named mutex — anti-reinfection primitive unique to malware families.',
      sources: 'EDR · Sandbox · Volatility · Process Monitor · Any.run',
      pivots: ['Process holding the mutex', 'Host where active', 'Malware family'],
      mitre: 'T1480 · T1622' }},
  { data: { id: 'pipe', type: 'artifact', category: 'endpoint', label: 'Named Pipe',
      desc: 'Windows named pipe — Cobalt Strike C2, inter-process comms, lateral movement.',
      sources: 'Sysmon Event 17/18 · EDR · PipeList · Process Monitor',
      pivots: ['Process communicating via pipe'],
      mitre: 'T1559.001 · T1021.002' }},
  { data: { id: 'host', type: 'artifact', category: 'endpoint', label: 'Host',
      desc: 'Endpoint, server, or workstation involved in the incident.',
      sources: 'EDR · SIEM · AD · Vuln Scanner · CMDB',
      pivots: ['Running processes', 'Logged-in users', 'Assigned IP', 'Network shares', 'RDP sessions'],
      mitre: 'T1018 · T1082 · T1016' }},
  { data: { id: 'share', type: 'artifact', category: 'endpoint', label: 'Network Share',
      desc: 'SMB/NFS share — lateral movement staging, data collection, exfil path.',
      sources: 'WinEvent 5140/5145 · EDR · Sysmon · Network traffic · AD',
      pivots: ['Host sharing it', 'User who accessed it'],
      mitre: 'T1021.002 · T1039 · T1074' }},
  { data: { id: 'event_id', type: 'artifact', category: 'endpoint', label: 'Event ID',
      desc: 'Windows Event ID — specific log event correlating process, user, or host.',
      sources: 'Windows Event Log · SIEM · Splunk · Elastic',
      pivots: ['Process logged', 'User logged', 'Host where event occurred'],
      mitre: 'T1562.002 · T1070.001' }},

  // ── ARTIFACT NODES — Identity ─────────────────────────────────────────
  { data: { id: 'user', type: 'artifact', category: 'identity', label: 'User',
      desc: 'User account — local, domain, or service account involved in the activity.',
      sources: 'AD logs · IAM · Okta · SIEM · UEBA',
      pivots: ['Hosts logged into', 'Processes executed', 'Email account', 'Cloud identity', 'Logon sessions', 'Kerberos tickets', 'SPN requests'],
      mitre: 'T1078 · T1087 · T1021' }},
  { data: { id: 'identity', type: 'artifact', category: 'identity', label: 'Identity',
      desc: 'Cloud / federated identity — Azure AD, AWS IAM, GCP SA — cloud access vector.',
      sources: 'Azure AD · AWS IAM · GCP SA · Okta · SIEM · CloudTrail',
      pivots: ['Cloud resources accessed', 'SPN that owns it', 'User mapped to it'],
      mitre: 'T1078.004 · T1136.003 · T1098' }},
  { data: { id: 'logon_session', type: 'artifact', category: 'identity', label: 'Logon Session',
      desc: 'Interactive/network logon session — token, privileges, and source context.',
      sources: 'WinEvent 4624/4625/4647 · SIEM · EDR · AD · Sysmon',
      pivots: ['Host where session occurred'],
      mitre: 'T1078 · T1021 · T1550' }},
  { data: { id: 'kerberos_ticket', type: 'artifact', category: 'identity', label: 'Kerb. Ticket',
      desc: 'Kerberos TGT/TGS — pass-the-ticket, golden ticket, Kerberoasting.',
      sources: 'WinEvent 4769/4770 · Mimikatz · Volatility · EDR · Rubeus',
      pivots: ['Service it grants access to'],
      mitre: 'T1558 · T1550.003 · T1558.003' }},
  { data: { id: 'spn', type: 'artifact', category: 'identity', label: 'SPN',
      desc: 'Service Principal Name — Kerberoasting target, service account enumeration.',
      sources: 'AD LDAP · WinEvent 4769 · BloodHound · PowerView · Impacket',
      pivots: ['Kerberos ticket generated', 'Service it represents', 'Identity that owns it'],
      mitre: 'T1558.003 · T1087.002' }},
  { data: { id: 'rdp_session', type: 'artifact', category: 'identity', label: 'RDP Session',
      desc: 'RDP session — lateral movement, credential exposure, remote access.',
      sources: 'WinEvent 4624/4778/4779 · EDR · NetFlow · Security Onion',
      pivots: ['User who initiated it', 'Host that accepted it'],
      mitre: 'T1021.001 · T1563.002' }},

  // ── ARTIFACT NODES — Email ────────────────────────────────────────────
  { data: { id: 'email', type: 'artifact', category: 'email', label: 'Email',
      desc: 'Phishing or suspicious email — headers, body, embedded URLs, attachments.',
      sources: 'Email Gateway · O365 Message Trace · SIEM · Proofpoint · Mimecast',
      pivots: ['Embedded URL', 'Attachment (→ Hash)', 'Sender domain'],
      mitre: 'T1566.001 · T1566.002 · T1598' }},
  { data: { id: 'attachment', type: 'artifact', category: 'email', label: 'Attachment',
      desc: 'Email attachment — document with macro, PE dropper, or archive payload.',
      sources: 'Email Gateway · Sandbox · AV · EDR · O365 ATP',
      pivots: ['File hash of attachment', 'Sandbox detonation'],
      mitre: 'T1566.001 · T1204.002 · T1027' }},

  // ── ARTIFACT NODES — Cloud ────────────────────────────────────────────
  { data: { id: 'cloud_resource', type: 'artifact', category: 'cloud', label: 'Cloud Resource',
      desc: 'S3 bucket, Azure blob, IAM role, Lambda, or cloud compute resource.',
      sources: 'CloudTrail · Azure Monitor · GCP Audit · GuardDuty · Defender for Cloud',
      pivots: ['Identity that accessed it', 'Data stored / exfiltrated'],
      mitre: 'T1078.004 · T1537 · T1530 · T1619' }},

  // ── ENRICHMENT NODES ──────────────────────────────────────────────────
  { data: { id: 'enr-rep',      type: 'enrichment', label: 'Reputation',    desc: 'Threat reputation from VT, OTX, AbuseIPDB.',                               sources: 'VirusTotal · OTX · AbuseIPDB · IBM X-Force' }},
  { data: { id: 'enr-whois',    type: 'enrichment', label: 'WHOIS / DNS',   desc: 'Domain registration, NS/MX records, registrant history.',                   sources: 'WHOIS · Passive DNS · RiskIQ · SecurityTrails' }},
  { data: { id: 'enr-geo',      type: 'enrichment', label: 'ASN / Geo',     desc: 'Autonomous System, geolocation, hosting provider, and org.',                sources: 'Shodan · IPinfo · MaxMind · Censys' }},
  { data: { id: 'enr-filemeta', type: 'enrichment', label: 'File Metadata', desc: 'PE headers, compile time, imphash, rich header, code signing.',              sources: 'VT file report · PE analysis · Sandbox' }},
  { data: { id: 'enr-sandbox',  type: 'enrichment', label: 'Sandbox',       desc: 'Dynamic analysis — runtime behavior, network IOCs, registry, dropped files.',sources: 'Any.run · Hybrid Analysis · VT Sandbox · Joe Sandbox' }},
  { data: { id: 'enr-procmeta', type: 'enrichment', label: 'Process Info',  desc: 'Command line, binary path, signing status, parent/child tree.',              sources: 'EDR · Sysmon · Windows Event Logs' }},

  // ── CONTEXT NODES ─────────────────────────────────────────────────────
  { data: { id: 'first-seen',  type: 'context', label: 'First/Last Seen', desc: 'When the artifact was first and last observed.',            sources: 'SIEM timeline · EDR history' }},
  { data: { id: 'frequency',   type: 'context', label: 'Frequency',        desc: 'How often artifact appears — beaconing intervals, logins.', sources: 'SIEM aggregation · Proxy logs' }},
  { data: { id: 'environment', type: 'context', label: 'Environment',      desc: 'Host/user classification: prod, dev, workstation, server.', sources: 'CMDB · AD OU · Asset inventory' }},
  { data: { id: 'ti-tags',     type: 'context', label: 'TI Tags',          desc: 'Threat intel tags: malware family, actor, campaign, TTPs.', sources: 'OTX pulses · VT community · MISP · ISACs' }},
  { data: { id: 'mitre',       type: 'context', label: 'MITRE TTP',        desc: 'ATT&CK technique mapping for the observed artifact.',       sources: 'Sigma rules · EDR detections · HYPOS' }},

  // ── PIVOT NODES ───────────────────────────────────────────────────────
  { data: { id: 'p-ip',      type: 'pivot', label: 'Related IPs',       desc: 'IPs sharing same ASN, cert, campaign, or infra block.' }},
  { data: { id: 'p-domain',  type: 'pivot', label: 'Related Domains',   desc: 'Domains on same IP, registrant, SSL cert, or DGA pattern.' }},
  { data: { id: 'p-url',     type: 'pivot', label: 'Related URLs',      desc: 'URLs on same domain/IP or serving similar payloads.' }},
  { data: { id: 'p-file',    type: 'pivot', label: 'Related Files',     desc: 'Files with same imphash, cert, or dropped by same parent.' }},
  { data: { id: 'p-process', type: 'pivot', label: 'Related Processes', desc: 'Child/parent processes or same hash across machines.' }},
  { data: { id: 'p-user',    type: 'pivot', label: 'Related Users',     desc: 'Users on same host, credential, or access scope.' }},
  { data: { id: 'p-host',    type: 'pivot', label: 'Related Hosts',     desc: 'Hosts with same user activity or as lateral move destination.' }},

  // ── CORRELATION NODES ─────────────────────────────────────────────────
  { data: { id: 'corr-asn',      type: 'correlation', label: 'Same ASN / Infra',  desc: 'Multiple IPs/domains on same ASN or infrastructure block.' }},
  { data: { id: 'corr-ssl',      type: 'correlation', label: 'Same SSL Cert',     desc: 'Domains/IPs sharing a TLS certificate.' }},
  { data: { id: 'corr-malware',  type: 'correlation', label: 'Same Malware',      desc: 'Files/processes attributed to same malware family.' }},
  { data: { id: 'corr-campaign', type: 'correlation', label: 'Same Campaign',     desc: 'Indicators linked to same threat actor or campaign.' }},
  { data: { id: 'corr-time',     type: 'correlation', label: 'Temporal Cluster',  desc: 'Events temporally clustered across multiple hosts.' }},

  // ── DECISION NODES ────────────────────────────────────────────────────
  { data: { id: 'dec-malicious',  type: 'decision', label: 'Malicious',  desc: 'High confidence — confirmed threat. Proceed with containment.' }},
  { data: { id: 'dec-suspicious', type: 'decision', label: 'Suspicious', desc: 'Medium confidence — requires further investigation.' }},
  { data: { id: 'dec-benign',     type: 'decision', label: 'Benign',     desc: 'Low/no threat signal — likely false positive.' }},
  { data: { id: 'dec-unknown',    type: 'decision', label: 'Unknown',    desc: 'Insufficient data — expand enrichment.' }},

  // ── ACTION NODES ──────────────────────────────────────────────────────
  { data: { id: 'act-block',    type: 'action', label: 'Block Indicator',   desc: 'Add IP/domain/hash to firewall, proxy, or EDR block list.' }},
  { data: { id: 'act-isolate',  type: 'action', label: 'Isolate Host',      desc: 'Network-isolate the compromised endpoint.' }},
  { data: { id: 'act-reset',    type: 'action', label: 'Reset Credentials', desc: 'Force password reset and session invalidation.' }},
  { data: { id: 'act-escalate', type: 'action', label: 'Escalate Incident', desc: 'Open formal incident, notify IR team, preserve evidence.' }},
  { data: { id: 'act-hunt',     type: 'action', label: 'Continue Hunting',  desc: 'Expand scope — pivot to related artifacts, run new queries.' }}
];

const GRAPH_EDGES = [
  // ── Cross-pivot edges — pivot_map (crossPivot: true, visible in SIMPLE) ──

  // IP
  { data: { id: 'ip-domain',      source: 'ip',    target: 'domain',      crossPivot: true, label: 'resolves_to' }},
  { data: { id: 'ip-fqdn',        source: 'ip',    target: 'fqdn',        crossPivot: true, label: 'resolves_to' }},
  { data: { id: 'ip-asn',         source: 'ip',    target: 'asn',         crossPivot: true, label: 'belongs_to' }},
  { data: { id: 'ip-port',        source: 'ip',    target: 'port',        crossPivot: true, label: 'connects_to' }},
  { data: { id: 'ip-service',     source: 'ip',    target: 'service',     crossPivot: true, label: 'hosts_service' }},
  { data: { id: 'ip-ssl_cert',    source: 'ip',    target: 'ssl_cert',    crossPivot: true, label: 'presents_cert' }},
  // Domain
  { data: { id: 'domain-ip',         source: 'domain', target: 'ip',         crossPivot: true, label: 'resolves_to' }},
  { data: { id: 'domain-fqdn',       source: 'domain', target: 'fqdn',       crossPivot: true, label: 'contains' }},
  { data: { id: 'domain-dns_record', source: 'domain', target: 'dns_record', crossPivot: true, label: 'has_record' }},
  { data: { id: 'domain-ssl_cert',   source: 'domain', target: 'ssl_cert',   crossPivot: true, label: 'uses_cert' }},
  // FQDN
  { data: { id: 'fqdn-ip',  source: 'fqdn', target: 'ip',  crossPivot: true, label: 'resolves_to' }},
  // DNS Query
  { data: { id: 'dnsq-domain',  source: 'dns_query', target: 'domain',  crossPivot: true, label: 'queries' }},
  { data: { id: 'dnsq-fqdn',    source: 'dns_query', target: 'fqdn',    crossPivot: true, label: 'queries' }},
  { data: { id: 'dnsq-process', source: 'dns_query', target: 'process', crossPivot: true, label: 'initiated_by' }},
  // URL
  { data: { id: 'url-domain',       source: 'url', target: 'domain',       crossPivot: true, label: 'belongs_to' }},
  { data: { id: 'url-ip',           source: 'url', target: 'ip',           crossPivot: true, label: 'connects_to' }},
  { data: { id: 'url-hash',         source: 'url', target: 'hash',         crossPivot: true, label: 'downloads' }},
  { data: { id: 'url-http_request', source: 'url', target: 'http_request', crossPivot: true, label: 'via_request' }},
  // HTTP Request
  { data: { id: 'httpreq-url',  source: 'http_request', target: 'url',        crossPivot: true, label: 'targets' }},
  { data: { id: 'httpreq-ua',   source: 'http_request', target: 'user_agent', crossPivot: true, label: 'uses' }},
  { data: { id: 'httpreq-proc', source: 'http_request', target: 'process',    crossPivot: true, label: 'initiated_by' }},
  // Hash
  { data: { id: 'hash-process',   source: 'hash', target: 'process',   crossPivot: true, label: 'executes_as' }},
  { data: { id: 'hash-file_path', source: 'hash', target: 'file_path', crossPivot: true, label: 'stored_as' }},
  { data: { id: 'hash-domain',    source: 'hash', target: 'domain',    crossPivot: true, label: 'contacts' }},
  { data: { id: 'hash-ip',        source: 'hash', target: 'ip',        crossPivot: true, label: 'contacts' }},
  // File Path
  { data: { id: 'filepath-process', source: 'file_path', target: 'process', crossPivot: true, label: 'executed_by' }},
  // Process (15 outgoing — self-loop omitted)
  { data: { id: 'proc-hash',     source: 'process', target: 'hash',           crossPivot: true, label: 'backed_by' }},
  { data: { id: 'proc-filepath', source: 'process', target: 'file_path',      crossPivot: true, label: 'runs_from' }},
  { data: { id: 'proc-ip',       source: 'process', target: 'ip',             crossPivot: true, label: 'network_conn' }},
  { data: { id: 'proc-domain',   source: 'process', target: 'domain',         crossPivot: true, label: 'dns_query' }},
  { data: { id: 'proc-host',     source: 'process', target: 'host',           crossPivot: true, label: 'runs_on' }},
  { data: { id: 'proc-user',     source: 'process', target: 'user',           crossPivot: true, label: 'executed_by' }},
  { data: { id: 'proc-registry', source: 'process', target: 'registry',       crossPivot: true, label: 'modifies' }},
  { data: { id: 'proc-task',     source: 'process', target: 'scheduled_task', crossPivot: true, label: 'creates' }},
  { data: { id: 'proc-service',  source: 'process', target: 'service',        crossPivot: true, label: 'controls' }},
  { data: { id: 'proc-mutex',    source: 'process', target: 'mutex',          crossPivot: true, label: 'creates' }},
  { data: { id: 'proc-pipe',     source: 'process', target: 'pipe',           crossPivot: true, label: 'via_pipe' }},
  { data: { id: 'proc-driver',   source: 'process', target: 'driver',         crossPivot: true, label: 'loads_driver' }},
  { data: { id: 'proc-dll',      source: 'process', target: 'dll',            crossPivot: true, label: 'loads_dll' }},
  { data: { id: 'proc-dnsq',     source: 'process', target: 'dns_query',      crossPivot: true, label: 'initiates' }},
  { data: { id: 'proc-httpreq',  source: 'process', target: 'http_request',   crossPivot: true, label: 'initiates' }},
  // User
  { data: { id: 'user-host',     source: 'user', target: 'host',            crossPivot: true, label: 'logs_into' }},
  { data: { id: 'user-process',  source: 'user', target: 'process',         crossPivot: true, label: 'executes' }},
  { data: { id: 'user-email',    source: 'user', target: 'email',           crossPivot: true, label: 'owns' }},
  { data: { id: 'user-identity', source: 'user', target: 'identity',        crossPivot: true, label: 'mapped_to' }},
  { data: { id: 'user-logon',    source: 'user', target: 'logon_session',   crossPivot: true, label: 'initiates' }},
  { data: { id: 'user-kerbtkt',  source: 'user', target: 'kerberos_ticket', crossPivot: true, label: 'authenticates' }},
  { data: { id: 'user-spn',      source: 'user', target: 'spn',             crossPivot: true, label: 'requests_tkt' }},
  // SPN
  { data: { id: 'spn-kerbtkt',  source: 'spn', target: 'kerberos_ticket', crossPivot: true, label: 'generates' }},
  { data: { id: 'spn-service',  source: 'spn', target: 'service',         crossPivot: true, label: 'represents' }},
  { data: { id: 'spn-identity', source: 'spn', target: 'identity',        crossPivot: true, label: 'owned_by' }},
  // Kerberos Ticket
  { data: { id: 'kerbtkt-service', source: 'kerberos_ticket', target: 'service', crossPivot: true, label: 'grants_access' }},
  // Host
  { data: { id: 'host-process', source: 'host', target: 'process',     crossPivot: true, label: 'runs' }},
  { data: { id: 'host-user',    source: 'host', target: 'user',        crossPivot: true, label: 'used_by' }},
  { data: { id: 'host-ip',      source: 'host', target: 'ip',          crossPivot: true, label: 'assigned' }},
  { data: { id: 'host-share',   source: 'host', target: 'share',       crossPivot: true, label: 'hosts' }},
  { data: { id: 'host-rdp',     source: 'host', target: 'rdp_session', crossPivot: true, label: 'accepts' }},
  // Email
  { data: { id: 'email-url',        source: 'email', target: 'url',        crossPivot: true, label: 'contains' }},
  { data: { id: 'email-attachment', source: 'email', target: 'attachment', crossPivot: true, label: 'contains' }},
  { data: { id: 'email-domain',     source: 'email', target: 'domain',     crossPivot: true, label: 'sender_domain' }},
  // Attachment
  { data: { id: 'attach-hash', source: 'attachment', target: 'hash', crossPivot: true, label: 'has_hash' }},
  // DNS Record
  { data: { id: 'dnsrec-ip', source: 'dns_record', target: 'ip', crossPivot: true, label: 'resolves_to' }},
  // SSL Cert
  { data: { id: 'sslcert-domain', source: 'ssl_cert', target: 'domain', crossPivot: true, label: 'issued_to' }},
  { data: { id: 'sslcert-ip',     source: 'ssl_cert', target: 'ip',     crossPivot: true, label: 'observed_on' }},
  // JA3
  { data: { id: 'ja3-ip', source: 'ja3', target: 'ip', crossPivot: true, label: 'observed_from' }},
  // Service
  { data: { id: 'service-port', source: 'service', target: 'port', crossPivot: true, label: 'listens_on' }},
  { data: { id: 'service-host', source: 'service', target: 'host', crossPivot: true, label: 'runs_on' }},
  // Logon Session
  { data: { id: 'logon-host', source: 'logon_session', target: 'host', crossPivot: true, label: 'occurs_on' }},
  // Share
  { data: { id: 'share-user', source: 'share', target: 'user', crossPivot: true, label: 'accessed_by' }},
  // RDP Session
  { data: { id: 'rdp-user', source: 'rdp_session', target: 'user', crossPivot: true, label: 'initiated_by' }},
  // Cloud Resource
  { data: { id: 'cloud-identity', source: 'cloud_resource', target: 'identity', crossPivot: true, label: 'accessed_by' }},
  // Event ID
  { data: { id: 'evtid-process', source: 'event_id', target: 'process', crossPivot: true, label: 'logs_process' }},
  { data: { id: 'evtid-user',    source: 'event_id', target: 'user',    crossPivot: true, label: 'logs_user' }},
  { data: { id: 'evtid-host',    source: 'event_id', target: 'host',    crossPivot: true, label: 'logs_host' }},
  // Code-signing cert (not in pivot_map but semantically linked)
  { data: { id: 'cert-hash', source: 'certificate', target: 'hash', crossPivot: true, label: 'signs' }},

  // ── Artifact → Enrichment (visible in FULL mode only) ─────────────────
  { data: { id: 'ip-enr-rep',       source: 'ip',       target: 'enr-rep'      }},
  { data: { id: 'domain-enr-rep',   source: 'domain',   target: 'enr-rep'      }},
  { data: { id: 'url-enr-rep',      source: 'url',      target: 'enr-rep'      }},
  { data: { id: 'sslcrt-enr-rep',   source: 'ssl_cert', target: 'enr-rep'      }},
  { data: { id: 'hash-enr-rep',     source: 'hash',     target: 'enr-rep'      }},
  { data: { id: 'ip-enr-whois',     source: 'ip',       target: 'enr-whois'    }},
  { data: { id: 'domain-enr-whois', source: 'domain',   target: 'enr-whois'    }},
  { data: { id: 'fqdn-enr-whois',   source: 'fqdn',     target: 'enr-whois'    }},
  { data: { id: 'ip-enr-geo',       source: 'ip',       target: 'enr-geo'      }},
  { data: { id: 'asn-enr-geo',      source: 'asn',      target: 'enr-geo'      }},
  { data: { id: 'hash-enr-fm',      source: 'hash',     target: 'enr-filemeta' }},
  { data: { id: 'dll-enr-fm',       source: 'dll',      target: 'enr-filemeta' }},
  { data: { id: 'drv-enr-fm',       source: 'driver',   target: 'enr-filemeta' }},
  { data: { id: 'hash-enr-sb',      source: 'hash',     target: 'enr-sandbox'  }},
  { data: { id: 'dll-enr-sb',       source: 'dll',      target: 'enr-sandbox'  }},
  { data: { id: 'proc-enr-pm',      source: 'process',  target: 'enr-procmeta' }},
  { data: { id: 'svc-enr-pm',       source: 'service',  target: 'enr-procmeta' }},

  // ── Artifact → Context ────────────────────────────────────────────────
  { data: { id: 'ip-ti',      source: 'ip',      target: 'ti-tags'    }},
  { data: { id: 'domain-ti',  source: 'domain',  target: 'ti-tags'    }},
  { data: { id: 'hash-ti',    source: 'hash',    target: 'ti-tags'    }},
  { data: { id: 'process-ti', source: 'process', target: 'ti-tags'    }},
  { data: { id: 'user-ti',    source: 'user',    target: 'ti-tags'    }},
  { data: { id: 'ip-mitre',   source: 'ip',      target: 'mitre'      }},
  { data: { id: 'proc-mitre', source: 'process', target: 'mitre'      }},
  { data: { id: 'user-mitre', source: 'user',    target: 'mitre'      }},
  { data: { id: 'hash-mitre', source: 'hash',    target: 'mitre'      }},
  { data: { id: 'ip-fseen',   source: 'ip',      target: 'first-seen' }},
  { data: { id: 'hash-fseen', source: 'hash',    target: 'first-seen' }},
  { data: { id: 'proc-fseen', source: 'process', target: 'first-seen' }},
  { data: { id: 'user-fseen', source: 'user',    target: 'first-seen' }},
  { data: { id: 'ip-freq',    source: 'ip',      target: 'frequency'  }},
  { data: { id: 'proc-freq',  source: 'process', target: 'frequency'  }},

  // ── Artifact → Correlation ────────────────────────────────────────────
  { data: { id: 'ip-corr-asn',   source: 'ip',       target: 'corr-asn'      }},
  { data: { id: 'asn-corr-asn',  source: 'asn',      target: 'corr-asn'      }},
  { data: { id: 'sslcrt-corr',   source: 'ssl_cert', target: 'corr-ssl'      }},
  { data: { id: 'hash-corr-mal', source: 'hash',     target: 'corr-malware'  }},
  { data: { id: 'dll-corr-mal',  source: 'dll',      target: 'corr-malware'  }},
  { data: { id: 'ip-corr-camp',  source: 'ip',       target: 'corr-campaign' }},
  { data: { id: 'dom-corr-camp', source: 'domain',   target: 'corr-campaign' }},
  { data: { id: 'hash-corr-c',   source: 'hash',     target: 'corr-campaign' }},
  { data: { id: 'evtid-corr-t',  source: 'event_id', target: 'corr-time'     }},
  { data: { id: 'host-corr-t',   source: 'host',     target: 'corr-time'     }},

  // ── Pivot helpers ─────────────────────────────────────────────────────
  { data: { id: 'p-ip-ip',    source: 'p-ip',      target: 'ip'      }},
  { data: { id: 'p-dom-dom',  source: 'p-domain',  target: 'domain'  }},
  { data: { id: 'p-url-url',  source: 'p-url',     target: 'url'     }},
  { data: { id: 'p-file-h',   source: 'p-file',    target: 'hash'    }},
  { data: { id: 'p-proc-p',   source: 'p-process', target: 'process' }},
  { data: { id: 'p-user-u',   source: 'p-user',    target: 'user'    }},
  { data: { id: 'p-host-h',   source: 'p-host',    target: 'host'    }},

  // ── Enrichment / Correlation → Decision ──────────────────────────────
  { data: { id: 'rep-dec-m', source: 'enr-rep',      target: 'dec-malicious'  }},
  { data: { id: 'rep-dec-s', source: 'enr-rep',      target: 'dec-suspicious' }},
  { data: { id: 'rep-dec-b', source: 'enr-rep',      target: 'dec-benign'     }},
  { data: { id: 'rep-dec-u', source: 'enr-rep',      target: 'dec-unknown'    }},
  { data: { id: 'cmal-dec',  source: 'corr-malware',  target: 'dec-malicious'  }},
  { data: { id: 'ccam-dec',  source: 'corr-campaign', target: 'dec-malicious'  }},
  { data: { id: 'casn-dec',  source: 'corr-asn',      target: 'dec-suspicious' }},
  { data: { id: 'cssl-dec',  source: 'corr-ssl',      target: 'dec-suspicious' }},
  { data: { id: 'ctim-dec',  source: 'corr-time',     target: 'dec-suspicious' }},

  // ── Decision → Action ─────────────────────────────────────────────────
  { data: { id: 'dm-block',   source: 'dec-malicious',  target: 'act-block'    }},
  { data: { id: 'dm-isolate', source: 'dec-malicious',  target: 'act-isolate'  }},
  { data: { id: 'dm-esc',     source: 'dec-malicious',  target: 'act-escalate' }},
  { data: { id: 'ds-hunt',    source: 'dec-suspicious', target: 'act-hunt'     }},
  { data: { id: 'ds-esc',     source: 'dec-suspicious', target: 'act-escalate' }},
  { data: { id: 'du-hunt',    source: 'dec-unknown',    target: 'act-hunt'     }},
  { data: { id: 'db-hunt',    source: 'dec-benign',     target: 'act-hunt'     }}
];

// ── ARTIFACT_PATHS — programmatic from GRAPH_EDGES ────────────────────────
const ARTIFACT_PATHS = {};
(function () {
  var MITRE_INFO = {
    ip: 'T1071.001 · T1090 · T1046 · T1016', domain: 'T1071 · T1566.002 · T1190 · T1584.001',
    fqdn: 'T1071 · T1568', url: 'T1566.002 · T1204.001 · T1071.001',
    dns_query: 'T1071.004 · T1568 · T1048.003', http_request: 'T1071.001 · T1105 · T1041',
    asn: 'T1090 · T1584.003', dns_record: 'T1584.001 · T1071.004',
    ssl_cert: 'T1553.004 · T1584 · T1090.002', ja3: 'T1071.001 · T1573',
    user_agent: 'T1071.001 · T1218', port: 'T1046 · T1571', certificate: 'T1553.002 · T1036.001',
    hash: 'T1027 · T1064 · T1204.002', file_path: 'T1074 · T1083 · T1036.005',
    process: 'T1059 · T1055 · T1003 · T1218', process_guid: 'T1057',
    dll: 'T1574.001 · T1574.002 · T1129', driver: 'T1014 · T1547.006 · T1068',
    service: 'T1543.003 · T1050 · T1021.002', registry: 'T1547.001 · T1112',
    scheduled_task: 'T1053.005', startup_item: 'T1547 · T1037', mutex: 'T1480',
    pipe: 'T1559.001', host: 'T1018 · T1082 · T1016', share: 'T1021.002 · T1039',
    event_id: 'T1562.002 · T1070.001', user: 'T1078 · T1087 · T1021',
    identity: 'T1078.004 · T1136.003 · T1098', logon_session: 'T1078 · T1021 · T1550',
    kerberos_ticket: 'T1558 · T1550.003 · T1558.003', spn: 'T1558.003 · T1087.002',
    rdp_session: 'T1021.001 · T1563.002', email: 'T1566.001 · T1566.002 · T1598',
    attachment: 'T1566.001 · T1204.002', cloud_resource: 'T1078.004 · T1537 · T1530'
  };
  var nbrs = {};
  GRAPH_NODES.forEach(function (n) { if (n.data.type === 'artifact') nbrs[n.data.id] = new Set([n.data.id]); });
  GRAPH_EDGES.forEach(function (e) {
    if (!e.data.crossPivot) return;
    var s = e.data.source, t = e.data.target;
    if (nbrs[s]) nbrs[s].add(t);
    if (nbrs[t]) nbrs[t].add(s);
  });
  var support = ['enr-rep','enr-whois','enr-geo','enr-filemeta','enr-sandbox','enr-procmeta',
    'first-seen','frequency','ti-tags','mitre',
    'dec-malicious','dec-suspicious','dec-benign','dec-unknown',
    'act-block','act-isolate','act-reset','act-escalate','act-hunt'];
  GRAPH_NODES.forEach(function (n) {
    if (n.data.type !== 'artifact') return;
    var id = n.data.id;
    ARTIFACT_PATHS[id] = {
      label: n.data.label, nodes: Array.from(nbrs[id]).concat(support),
      mitre: MITRE_INFO[id] || 'See MITRE ATT&CK', sources: n.data.sources
    };
  });
}());
