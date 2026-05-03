// PIVEX — graph-data.js  v9.0
// 41 artifact nodes + directed cross-pivot edges only (no support nodes)

const GRAPH_NODES = [
  // ── ARTIFACT NODES — Network (15) ────────────────────────────────────────
  { data: { id: 'ip', type: 'artifact', category: 'network', label: 'IP Address',
      desc: 'IPv4/IPv6 address observed in logs, alerts, or network telemetry.',
      sources: 'Firewall · SIEM · NetFlow · Proxy · EDR',
      pivots: ['Passive DNS → Domain/FQDN', 'ASN / hosting context', 'Open ports', 'SSL cert presented', 'RDP sessions', 'MAC address on LAN', 'Network traffic flows'],
      mitre: 'T1071.001 · T1090 · T1046 · T1016' }},
  { data: { id: 'domain', type: 'artifact', category: 'network', label: 'Domain',
      desc: 'Domain name seen in DNS queries, HTTP traffic, or email headers.',
      sources: 'DNS logs · Proxy · Email Gateway · Passive DNS',
      pivots: ['Resolved IPs', 'FQDNs on domain', 'DNS records', 'URLs on domain', 'SSL cert used', 'Code-signing cert'],
      mitre: 'T1071 · T1566.002 · T1190 · T1584.001' }},
  { data: { id: 'fqdn', type: 'artifact', category: 'network', label: 'FQDN',
      desc: 'Fully qualified domain name — precise subdomain used in C2 or delivery.',
      sources: 'DNS logs · Proxy · EDR · Sysmon Event 22',
      pivots: ['Parent domain', 'Resolved IP', 'DNS records', 'URLs on this FQDN'],
      mitre: 'T1071 · T1568' }},
  { data: { id: 'url', type: 'artifact', category: 'network', label: 'URL',
      desc: 'Full URL from proxy, email links, or browser history.',
      sources: 'Proxy logs · Email Gateway · Browser history · EDR',
      pivots: ['Parent domain', 'FQDN', 'Hosting IP', 'HTTP request details', 'Downloaded payload (→ Hash)', 'User-Agent used'],
      mitre: 'T1566.002 · T1204.001 · T1071.001' }},
  { data: { id: 'dns_query', type: 'artifact', category: 'network', label: 'DNS Query',
      desc: 'DNS resolution request — reveals C2 beaconing, DGA, and exfil patterns.',
      sources: 'DNS logs · Sysmon Event 22 · EDR · Network tap',
      pivots: ['Queried domain', 'Resolved IP', 'FQDN queried', 'DNS record returned'],
      mitre: 'T1071.004 · T1568 · T1048.003' }},
  { data: { id: 'http_request', type: 'artifact', category: 'network', label: 'HTTP Request',
      desc: 'HTTP/S request with method, headers, user-agent, and response.',
      sources: 'Proxy · Firewall · EDR · Zeek / Suricata · Network sensor',
      pivots: ['Target URL', 'Domain contacted', 'Destination IP', 'User-Agent string', 'Payload hash', 'JA3 fingerprint'],
      mitre: 'T1071.001 · T1105 · T1041' }},
  { data: { id: 'asn', type: 'artifact', category: 'network', label: 'ASN',
      desc: 'Autonomous System Number — identifies hosting provider, CDN, or proxy infra.',
      sources: 'Shodan · BGP data · IPinfo · MaxMind · RIPE',
      pivots: ['IPs in this ASN', 'Domains on this ASN', 'Cloud resources in this ASN'],
      mitre: 'T1090 · T1584.003' }},
  { data: { id: 'dns_record', type: 'artifact', category: 'network', label: 'DNS Record',
      desc: 'A/AAAA/MX/NS/TXT/CNAME — pivots from domain to IP infrastructure.',
      sources: 'WHOIS · Passive DNS · RiskIQ · Farsight · SecurityTrails',
      pivots: ['Parent domain', 'Resolved IP', 'FQDN', 'SSL cert on that IP'],
      mitre: 'T1584.001 · T1071.004' }},
  { data: { id: 'ssl_cert', type: 'artifact', category: 'network', label: 'SSL Cert',
      desc: 'SSL/TLS certificate — serial, CN, SAN — strong infrastructure clustering.',
      sources: 'Censys · Shodan · crt.sh · Passive DNS · JARM',
      pivots: ['Domain it was issued to', 'IPs where observed', 'JA3 clients using it', 'Code-signing cert chain'],
      mitre: 'T1553.004 · T1584 · T1090.002' }},
  { data: { id: 'ja3', type: 'artifact', category: 'network', label: 'JA3 Hash',
      desc: 'TLS client fingerprint — identifies malware TLS implementation uniquely.',
      sources: 'Network sensor · Zeek · Suricata · PCAP',
      pivots: ['SSL cert negotiated', 'Source IP using this fingerprint', 'User-Agent correlated', 'HTTP requests via this TLS'],
      mitre: 'T1071.001 · T1573' }},
  { data: { id: 'user_agent', type: 'artifact', category: 'network', label: 'User Agent',
      desc: 'HTTP User-Agent string — identifies tool, framework, or spoofed browser.',
      sources: 'Proxy · Zeek · Firewall · SIEM',
      pivots: ['HTTP requests using this UA', 'URLs accessed', 'Process (browser / tool)'],
      mitre: 'T1071.001 · T1218' }},
  { data: { id: 'port', type: 'artifact', category: 'network', label: 'Port',
      desc: 'Network port — anomalous service port indicating C2, pivot, or scanning.',
      sources: 'Firewall logs · Shodan · EDR · Nmap · Masscan',
      pivots: ['IP exposing this port', 'Service running on it', 'Network traffic on port', 'Vulnerability associated'],
      mitre: 'T1046 · T1571' }},
  { data: { id: 'certificate', type: 'artifact', category: 'network', label: 'Code-Sign Cert',
      desc: 'Code-signing certificate — authenticates binary or indicates stolen signing.',
      sources: 'VT code-signing · Censys · VirusTotal · PE analysis',
      pivots: ['SSL cert in same chain', 'Domain cert issued to', 'IP where observed', 'Cloud resource using it'],
      mitre: 'T1553.002 · T1036.001' }},
  { data: { id: 'network_traffic', type: 'artifact', category: 'network', label: 'Net Traffic',
      desc: 'NetFlow/PCAP session record — port, protocol, volume, and timing metadata.',
      sources: 'NetFlow · Zeek · Suricata · PCAP · Firewall · Network sensor',
      pivots: ['Source/destination IP', 'Port / protocol', 'Service associated', 'User-Agent (if HTTP)', 'JA3 fingerprint'],
      mitre: 'T1040 · T1046 · T1071' }},
  { data: { id: 'mac_address', type: 'artifact', category: 'network', label: 'MAC Address',
      desc: 'Physical NIC identifier — DHCP lease pivots, ARP spoofing, rogue device tracking.',
      sources: 'DHCP logs · ARP tables · EDR · Network sensor · Switch logs',
      pivots: ['Host with this MAC', 'IP assigned via DHCP'],
      mitre: 'T1016 · T1049' }},

  // ── ARTIFACT NODES — Endpoint (20) ───────────────────────────────────────
  { data: { id: 'hash', type: 'artifact', category: 'endpoint', label: 'File Hash',
      desc: 'MD5/SHA1/SHA256 of a file on disk, in memory, or from email attachment.',
      sources: 'EDR · AV · Sandbox · MalwareBazaar · Email scan',
      pivots: ['File path on disk', 'Executed process', 'DLL loads', 'Command line used'],
      mitre: 'T1027 · T1064 · T1204.002 · T1059' }},
  { data: { id: 'file_path', type: 'artifact', category: 'endpoint', label: 'File Path',
      desc: 'File / directory path — drop locations, staging dirs, LOLBin paths.',
      sources: 'EDR · Sysmon Event 11 · Windows Security · MFT · USN Journal',
      pivots: ['Hash at this path', 'Process spawned from here', 'DLL at path', 'Driver at path', 'Scheduled task referencing it', 'Startup item', 'Prefetch entry'],
      mitre: 'T1074 · T1083 · T1036.005' }},
  { data: { id: 'process', type: 'artifact', category: 'endpoint', label: 'Process',
      desc: 'Running or historical process — command line, parent, hash, and network activity.',
      sources: 'EDR · Sysmon Event 1 · WinEvent 4688 · Process Monitor',
      pivots: ['Command line args', 'Parent process', 'DLL loads', 'Registry writes', 'Mutex created', 'Pipe / named pipe', 'User context', 'Host', 'File path', 'WMI queries'],
      mitre: 'T1059 · T1055 · T1003 · T1218 · T1071' }},
  { data: { id: 'parent_process', type: 'artifact', category: 'endpoint', label: 'Parent Proc',
      desc: 'Parent process — process tree correlation for injection and spawn-chain analysis.',
      sources: 'EDR · Sysmon Event 1 · WinEvent 4688 · Process Monitor',
      pivots: ['Child processes spawned', 'Command line of parent', 'User context', 'DLL loads'],
      mitre: 'T1055 · T1134 · T1059' }},
  { data: { id: 'command_line', type: 'artifact', category: 'endpoint', label: 'Command Line',
      desc: 'Full command-line string — LOLBin abuse, encoded payloads, script execution.',
      sources: 'EDR · Sysmon Event 1 · WinEvent 4688 · PowerShell logs · ScriptBlock',
      pivots: ['Process executing it', 'File path referenced', 'Registry key', 'Scheduled task', 'Hash of binary', 'User who ran it', 'WMI query embedded'],
      mitre: 'T1059 · T1027.010 · T1218' }},
  { data: { id: 'service', type: 'artifact', category: 'endpoint', label: 'Service',
      desc: 'Windows service — malicious installs, driver loads, privilege escalation.',
      sources: 'Sysmon Event 6 · EDR · WinEvent 7045 · sc.exe · Services registry',
      pivots: ['Port it listens on', 'Host where running', 'Process backing it', 'Vulnerability exploited', 'Driver associated'],
      mitre: 'T1543.003 · T1050 · T1021.002' }},
  { data: { id: 'registry', type: 'artifact', category: 'endpoint', label: 'Registry Key',
      desc: 'Windows registry key/value — persistence, configuration, and malware indicators.',
      sources: 'Sysmon 12/13/14 · EDR · WinEvent 4657 · Autoruns · reg.exe',
      pivots: ['Process that modified it', 'Command line in value', 'Scheduled task', 'Startup item', 'DLL referenced', 'Driver reference'],
      mitre: 'T1547.001 · T1112' }},
  { data: { id: 'scheduled_task', type: 'artifact', category: 'endpoint', label: 'Sched. Task',
      desc: 'Windows scheduled task — persistence and lateral execution mechanism.',
      sources: 'Sysmon Event 11 · EDR · Task Scheduler logs · WinEvent 4698',
      pivots: ['Command line in action', 'Process it spawns', 'File path of executable', 'User who created it', 'Registry key backing it'],
      mitre: 'T1053.005 · T1053' }},
  { data: { id: 'startup_item', type: 'artifact', category: 'endpoint', label: 'Startup Item',
      desc: 'Startup folder, run key, or IFEO entry — persistent execution after reboot.',
      sources: 'Autoruns · EDR · Sysmon · Registry audit · WinEvent 4688',
      pivots: ['File path executed', 'Registry key backing it', 'Process executed on startup', 'DLL loaded'],
      mitre: 'T1547 · T1037' }},
  { data: { id: 'dll', type: 'artifact', category: 'endpoint', label: 'DLL',
      desc: 'DLL — hijacking, sideloading, or reflective injection indicator.',
      sources: 'EDR · Sysmon Event 7 · Process Monitor · PE analysis · VT',
      pivots: ['Process that loaded it', 'File path on disk', 'Hash of DLL', 'Driver associated', 'Mutex created'],
      mitre: 'T1574.001 · T1574.002 · T1129' }},
  { data: { id: 'mutex', type: 'artifact', category: 'endpoint', label: 'Mutex',
      desc: 'Named mutex — anti-reinfection primitive unique to malware families.',
      sources: 'EDR · Sandbox · Volatility · Process Monitor · Any.run',
      pivots: ['Process holding the mutex', 'DLL creating it', 'Hash of binary'],
      mitre: 'T1480 · T1622' }},
  { data: { id: 'pipe', type: 'artifact', category: 'endpoint', label: 'Pipe',
      desc: 'Windows named pipe — Cobalt Strike C2, inter-process comms, lateral movement.',
      sources: 'Sysmon Event 17/18 · EDR · PipeList · Process Monitor',
      pivots: ['Process communicating via pipe', 'User context', 'Host'],
      mitre: 'T1559.001 · T1021.002' }},
  { data: { id: 'driver', type: 'artifact', category: 'endpoint', label: 'Driver',
      desc: 'Kernel driver load — rootkits, bootkits, or BYOD attacks.',
      sources: 'Sysmon Event 6 · EDR · WinEvent 7045 · DriverQuery · WinPmem',
      pivots: ['File path on disk', 'Hash of driver', 'Service that loads it', 'Process that loaded it', 'DLL associated'],
      mitre: 'T1014 · T1547.006 · T1068' }},
  { data: { id: 'host', type: 'artifact', category: 'endpoint', label: 'Host',
      desc: 'Endpoint, server, or workstation involved in the incident.',
      sources: 'EDR · SIEM · AD · Vuln Scanner · CMDB',
      pivots: ['Assigned IP', 'MAC address', 'Logged-in users', 'Running processes', 'RDP sessions', 'Network shares', 'Drivers loaded', 'Vulnerabilities present', 'Event IDs on host'],
      mitre: 'T1018 · T1082 · T1016' }},
  { data: { id: 'share', type: 'artifact', category: 'endpoint', label: 'Network Share',
      desc: 'SMB/NFS share — lateral movement staging, data collection, exfil path.',
      sources: 'WinEvent 5140/5145 · EDR · Sysmon · Network traffic · AD',
      pivots: ['Host sharing it', 'IP of share host', 'User who accessed it', 'Files on share (→ File Path)'],
      mitre: 'T1021.002 · T1039 · T1074' }},
  { data: { id: 'event_id', type: 'artifact', category: 'endpoint', label: 'Event ID',
      desc: 'Windows Event ID — specific log event correlating process, user, or host.',
      sources: 'Windows Event Log · SIEM · Splunk · Elastic',
      pivots: ['Process logged by event', 'User in event', 'Host where event occurred', 'Registry operation logged'],
      mitre: 'T1562.002 · T1070.001' }},
  { data: { id: 'named_pipe', type: 'artifact', category: 'endpoint', label: 'Named Pipe',
      desc: 'Named pipe path — SMB lateral movement channel, default Cobalt Strike pipe names.',
      sources: 'Sysmon Event 17/18 · EDR · PipeList · Network traffic (SMB)',
      pivots: ['Process creating/accessing pipe', 'User context', 'Host', 'DLL injecting via pipe'],
      mitre: 'T1559.001 · T1021.002' }},
  { data: { id: 'wmi_query', type: 'artifact', category: 'endpoint', label: 'WMI Query',
      desc: 'WMI query or event subscription — lateral execution and persistence vector.',
      sources: 'Sysmon Events 19-21 · EDR · WinEvent · WMI-Activity log',
      pivots: ['Process that issued query', 'User who ran it', 'Command line embedded', 'Scheduled task via WMI', 'Registry for persistence'],
      mitre: 'T1047 · T1546.003' }},
  { data: { id: 'prefetch', type: 'artifact', category: 'endpoint', label: 'Prefetch',
      desc: 'Windows Prefetch file — execution evidence even after binary deletion.',
      sources: 'EDR · KAPE · Forensic imaging · WinPrefetchView · PECmd',
      pivots: ['File path of executed binary', 'Process from execution', 'Hash of binary', 'DLL loads recorded'],
      mitre: 'T1083 · T1027' }},
  { data: { id: 'vulnerability_id', type: 'artifact', category: 'endpoint', label: 'Vuln ID',
      desc: 'CVE / vulnerability identifier — links exploit activity to host and service.',
      sources: 'NVD · CISA KEV · Tenable · Qualys · Shodan · EDR',
      pivots: ['Affected host', 'Affected service', 'Cloud resource affected', 'Port associated'],
      mitre: 'T1190 · T1068 · T1203' }},

  // ── ARTIFACT NODES — Identity (3) ────────────────────────────────────────
  { data: { id: 'user', type: 'artifact', category: 'identity', label: 'User',
      desc: 'User account — local, domain, or service account involved in the activity.',
      sources: 'AD logs · IAM · Okta · SIEM · UEBA',
      pivots: ['Hosts logged into', 'Email account', 'Cloud identity', 'Scheduled tasks created', 'Cloud resource accessed', 'RDP sessions'],
      mitre: 'T1078 · T1087 · T1021' }},
  { data: { id: 'identity', type: 'artifact', category: 'identity', label: 'Identity',
      desc: 'Cloud / federated identity — Azure AD, AWS IAM, GCP SA — cloud access vector.',
      sources: 'Azure AD · AWS IAM · GCP SA · Okta · SIEM · CloudTrail',
      pivots: ['User mapped to it', 'Email account', 'Host accessing cloud', 'Cloud resource accessed'],
      mitre: 'T1078.004 · T1136.003 · T1098' }},
  { data: { id: 'rdp_session', type: 'artifact', category: 'identity', label: 'RDP Session',
      desc: 'RDP session — lateral movement, credential exposure, remote access.',
      sources: 'WinEvent 4624/4778/4779 · EDR · NetFlow · Security Onion',
      pivots: ['Destination host', 'Source IP', 'User who initiated it', 'Event ID logged'],
      mitre: 'T1021.001 · T1563.002' }},

  // ── ARTIFACT NODES — Email (2) ────────────────────────────────────────────
  { data: { id: 'email', type: 'artifact', category: 'email', label: 'Email',
      desc: 'Phishing or suspicious email — headers, body, embedded URLs, attachments.',
      sources: 'Email Gateway · O365 Message Trace · SIEM · Proofpoint · Mimecast',
      pivots: ['Attachment file', 'Payload hash', 'Embedded URL', 'Sender domain', 'Cloud identity linked', 'User account'],
      mitre: 'T1566.001 · T1566.002 · T1598' }},
  { data: { id: 'attachment', type: 'artifact', category: 'email', label: 'Attachment',
      desc: 'Email attachment — document with macro, PE dropper, or archive payload.',
      sources: 'Email Gateway · Sandbox · AV · EDR · O365 ATP',
      pivots: ['File hash', 'File path if dropped', 'URL in document', 'Domain in document'],
      mitre: 'T1566.001 · T1204.002 · T1027' }},

  // ── ARTIFACT NODES — Cloud (1) ────────────────────────────────────────────
  { data: { id: 'cloud_resource', type: 'artifact', category: 'cloud', label: 'Cloud Resource',
      desc: 'S3 bucket, Azure blob, IAM role, Lambda, or cloud compute resource.',
      sources: 'CloudTrail · Azure Monitor · GCP Audit · GuardDuty · Defender for Cloud',
      pivots: ['Source IP of access', 'User account', 'Cloud identity (IAM)', 'ASN of accessor', 'Service associated', 'Vulnerability present'],
      mitre: 'T1078.004 · T1537 · T1530 · T1619' }}
];

const GRAPH_EDGES = [
  // ── Cross-pivot edges (all artifact-to-artifact, directed) ────────────────

  // IP
  { data: { id: 'ip-domain',        source: 'ip',    target: 'domain',          crossPivot: true, label: 'resolves_to' }},
  { data: { id: 'ip-fqdn',          source: 'ip',    target: 'fqdn',            crossPivot: true, label: 'resolves_to' }},
  { data: { id: 'ip-asn',           source: 'ip',    target: 'asn',             crossPivot: true, label: 'belongs_to' }},
  { data: { id: 'ip-port',          source: 'ip',    target: 'port',            crossPivot: true, label: 'exposes' }},
  { data: { id: 'ip-ssl_cert',      source: 'ip',    target: 'ssl_cert',        crossPivot: true, label: 'presents_cert' }},
  { data: { id: 'ip-rdp_session',   source: 'ip',    target: 'rdp_session',     crossPivot: true, label: 'source_of' }},
  { data: { id: 'ip-mac_address',   source: 'ip',    target: 'mac_address',     crossPivot: true, label: 'assigned_to' }},
  { data: { id: 'ip-network_traffic', source: 'ip',  target: 'network_traffic', crossPivot: true, label: 'seen_in' }},

  // Domain
  { data: { id: 'domain-ip',         source: 'domain', target: 'ip',         crossPivot: true, label: 'resolves_to' }},
  { data: { id: 'domain-fqdn',       source: 'domain', target: 'fqdn',       crossPivot: true, label: 'contains' }},
  { data: { id: 'domain-dns_record', source: 'domain', target: 'dns_record', crossPivot: true, label: 'has_record' }},
  { data: { id: 'domain-url',        source: 'domain', target: 'url',        crossPivot: true, label: 'hosts' }},
  { data: { id: 'domain-ssl_cert',   source: 'domain', target: 'ssl_cert',   crossPivot: true, label: 'uses_cert' }},
  { data: { id: 'domain-certificate',source: 'domain', target: 'certificate',crossPivot: true, label: 'code_signed_by' }},

  // FQDN
  { data: { id: 'fqdn-domain',     source: 'fqdn', target: 'domain',     crossPivot: true, label: 'child_of' }},
  { data: { id: 'fqdn-ip',         source: 'fqdn', target: 'ip',         crossPivot: true, label: 'resolves_to' }},
  { data: { id: 'fqdn-dns_record', source: 'fqdn', target: 'dns_record', crossPivot: true, label: 'has_record' }},
  { data: { id: 'fqdn-url',        source: 'fqdn', target: 'url',        crossPivot: true, label: 'hosts' }},

  // URL
  { data: { id: 'url-domain',       source: 'url', target: 'domain',       crossPivot: true, label: 'belongs_to' }},
  { data: { id: 'url-fqdn',         source: 'url', target: 'fqdn',         crossPivot: true, label: 'belongs_to' }},
  { data: { id: 'url-ip',           source: 'url', target: 'ip',           crossPivot: true, label: 'connects_to' }},
  { data: { id: 'url-http_request', source: 'url', target: 'http_request', crossPivot: true, label: 'via_request' }},
  { data: { id: 'url-hash',         source: 'url', target: 'hash',         crossPivot: true, label: 'downloads' }},
  { data: { id: 'url-user_agent',   source: 'url', target: 'user_agent',   crossPivot: true, label: 'uses_ua' }},

  // DNS Query
  { data: { id: 'dnsq-domain',     source: 'dns_query', target: 'domain',     crossPivot: true, label: 'queries' }},
  { data: { id: 'dnsq-ip',         source: 'dns_query', target: 'ip',         crossPivot: true, label: 'resolves_to' }},
  { data: { id: 'dnsq-fqdn',       source: 'dns_query', target: 'fqdn',       crossPivot: true, label: 'queries' }},
  { data: { id: 'dnsq-dns_record', source: 'dns_query', target: 'dns_record', crossPivot: true, label: 'returns' }},

  // HTTP Request
  { data: { id: 'httpreq-url',       source: 'http_request', target: 'url',        crossPivot: true, label: 'targets' }},
  { data: { id: 'httpreq-domain',    source: 'http_request', target: 'domain',     crossPivot: true, label: 'contacts' }},
  { data: { id: 'httpreq-ip',        source: 'http_request', target: 'ip',         crossPivot: true, label: 'connects_to' }},
  { data: { id: 'httpreq-ua',        source: 'http_request', target: 'user_agent', crossPivot: true, label: 'uses' }},
  { data: { id: 'httpreq-hash',      source: 'http_request', target: 'hash',       crossPivot: true, label: 'delivers' }},
  { data: { id: 'httpreq-ja3',       source: 'http_request', target: 'ja3',        crossPivot: true, label: 'fingerprinted_by' }},

  // Hash
  { data: { id: 'hash-file_path',    source: 'hash', target: 'file_path',    crossPivot: true, label: 'stored_as' }},
  { data: { id: 'hash-process',      source: 'hash', target: 'process',      crossPivot: true, label: 'executes_as' }},
  { data: { id: 'hash-dll',          source: 'hash', target: 'dll',          crossPivot: true, label: 'loaded_as' }},
  { data: { id: 'hash-command_line', source: 'hash', target: 'command_line', crossPivot: true, label: 'invoked_via' }},

  // File Path
  { data: { id: 'filepath-hash',           source: 'file_path', target: 'hash',           crossPivot: true, label: 'hashes_to' }},
  { data: { id: 'filepath-process',        source: 'file_path', target: 'process',        crossPivot: true, label: 'executed_by' }},
  { data: { id: 'filepath-dll',            source: 'file_path', target: 'dll',            crossPivot: true, label: 'is_dll' }},
  { data: { id: 'filepath-driver',         source: 'file_path', target: 'driver',         crossPivot: true, label: 'is_driver' }},
  { data: { id: 'filepath-scheduled_task', source: 'file_path', target: 'scheduled_task', crossPivot: true, label: 'referenced_by' }},
  { data: { id: 'filepath-startup_item',   source: 'file_path', target: 'startup_item',   crossPivot: true, label: 'referenced_by' }},
  { data: { id: 'filepath-prefetch',       source: 'file_path', target: 'prefetch',       crossPivot: true, label: 'has_prefetch' }},

  // Process
  { data: { id: 'proc-command_line',  source: 'process', target: 'command_line',  crossPivot: true, label: 'launched_with' }},
  { data: { id: 'proc-parent',        source: 'process', target: 'parent_process',crossPivot: true, label: 'spawned_by' }},
  { data: { id: 'proc-dll',          source: 'process', target: 'dll',           crossPivot: true, label: 'loads_dll' }},
  { data: { id: 'proc-registry',     source: 'process', target: 'registry',      crossPivot: true, label: 'modifies' }},
  { data: { id: 'proc-mutex',        source: 'process', target: 'mutex',         crossPivot: true, label: 'creates' }},
  { data: { id: 'proc-pipe',         source: 'process', target: 'pipe',          crossPivot: true, label: 'uses_pipe' }},
  { data: { id: 'proc-named_pipe',   source: 'process', target: 'named_pipe',    crossPivot: true, label: 'uses_named_pipe' }},
  { data: { id: 'proc-user',         source: 'process', target: 'user',          crossPivot: true, label: 'executed_by' }},
  { data: { id: 'proc-host',         source: 'process', target: 'host',          crossPivot: true, label: 'runs_on' }},
  { data: { id: 'proc-file_path',    source: 'process', target: 'file_path',     crossPivot: true, label: 'runs_from' }},
  { data: { id: 'proc-wmi_query',    source: 'process', target: 'wmi_query',     crossPivot: true, label: 'issues' }},

  // Parent Process
  { data: { id: 'parent-process',      source: 'parent_process', target: 'process',      crossPivot: true, label: 'spawns' }},
  { data: { id: 'parent-command_line', source: 'parent_process', target: 'command_line', crossPivot: true, label: 'uses' }},
  { data: { id: 'parent-user',         source: 'parent_process', target: 'user',         crossPivot: true, label: 'context' }},
  { data: { id: 'parent-dll',          source: 'parent_process', target: 'dll',          crossPivot: true, label: 'loads_dll' }},

  // Command Line
  { data: { id: 'cmdline-process',        source: 'command_line', target: 'process',        crossPivot: true, label: 'executes' }},
  { data: { id: 'cmdline-file_path',      source: 'command_line', target: 'file_path',      crossPivot: true, label: 'references' }},
  { data: { id: 'cmdline-registry',       source: 'command_line', target: 'registry',       crossPivot: true, label: 'modifies' }},
  { data: { id: 'cmdline-scheduled_task', source: 'command_line', target: 'scheduled_task', crossPivot: true, label: 'creates' }},
  { data: { id: 'cmdline-hash',           source: 'command_line', target: 'hash',           crossPivot: true, label: 'invokes' }},
  { data: { id: 'cmdline-user',           source: 'command_line', target: 'user',           crossPivot: true, label: 'run_by' }},
  { data: { id: 'cmdline-wmi_query',      source: 'command_line', target: 'wmi_query',      crossPivot: true, label: 'contains' }},

  // User
  { data: { id: 'user-host',           source: 'user', target: 'host',           crossPivot: true, label: 'logs_into' }},
  { data: { id: 'user-email',          source: 'user', target: 'email',          crossPivot: true, label: 'owns_email' }},
  { data: { id: 'user-identity',       source: 'user', target: 'identity',       crossPivot: true, label: 'mapped_to' }},
  { data: { id: 'user-scheduled_task', source: 'user', target: 'scheduled_task', crossPivot: true, label: 'created' }},
  { data: { id: 'user-cloud_resource', source: 'user', target: 'cloud_resource', crossPivot: true, label: 'accessed' }},
  { data: { id: 'user-rdp_session',    source: 'user', target: 'rdp_session',    crossPivot: true, label: 'initiated' }},

  // Identity
  { data: { id: 'identity-user',           source: 'identity', target: 'user',           crossPivot: true, label: 'belongs_to' }},
  { data: { id: 'identity-email',          source: 'identity', target: 'email',          crossPivot: true, label: 'linked_email' }},
  { data: { id: 'identity-host',           source: 'identity', target: 'host',           crossPivot: true, label: 'accessed_from' }},
  { data: { id: 'identity-cloud_resource', source: 'identity', target: 'cloud_resource', crossPivot: true, label: 'accesses' }},

  // Host
  { data: { id: 'host-ip',               source: 'host', target: 'ip',               crossPivot: true, label: 'assigned' }},
  { data: { id: 'host-mac_address',      source: 'host', target: 'mac_address',      crossPivot: true, label: 'has_mac' }},
  { data: { id: 'host-user',             source: 'host', target: 'user',             crossPivot: true, label: 'used_by' }},
  { data: { id: 'host-process',          source: 'host', target: 'process',          crossPivot: true, label: 'runs' }},
  { data: { id: 'host-rdp_session',      source: 'host', target: 'rdp_session',      crossPivot: true, label: 'accepts' }},
  { data: { id: 'host-share',            source: 'host', target: 'share',            crossPivot: true, label: 'hosts' }},
  { data: { id: 'host-driver',           source: 'host', target: 'driver',           crossPivot: true, label: 'loads_driver' }},
  { data: { id: 'host-vulnerability_id', source: 'host', target: 'vulnerability_id', crossPivot: true, label: 'has_vuln' }},
  { data: { id: 'host-event_id',         source: 'host', target: 'event_id',         crossPivot: true, label: 'generates' }},

  // Email
  { data: { id: 'email-attachment', source: 'email', target: 'attachment',    crossPivot: true, label: 'contains' }},
  { data: { id: 'email-hash',       source: 'email', target: 'hash',          crossPivot: true, label: 'attachment_hash' }},
  { data: { id: 'email-url',        source: 'email', target: 'url',           crossPivot: true, label: 'contains_link' }},
  { data: { id: 'email-domain',     source: 'email', target: 'domain',        crossPivot: true, label: 'sender_domain' }},
  { data: { id: 'email-identity',   source: 'email', target: 'identity',      crossPivot: true, label: 'linked_identity' }},
  { data: { id: 'email-user',       source: 'email', target: 'user',          crossPivot: true, label: 'recipient' }},

  // Attachment
  { data: { id: 'attach-hash',      source: 'attachment', target: 'hash',      crossPivot: true, label: 'has_hash' }},
  { data: { id: 'attach-file_path', source: 'attachment', target: 'file_path', crossPivot: true, label: 'dropped_to' }},
  { data: { id: 'attach-url',       source: 'attachment', target: 'url',       crossPivot: true, label: 'contains_url' }},
  { data: { id: 'attach-domain',    source: 'attachment', target: 'domain',    crossPivot: true, label: 'contacts_domain' }},

  // ASN
  { data: { id: 'asn-ip',           source: 'asn', target: 'ip',           crossPivot: true, label: 'contains_ip' }},
  { data: { id: 'asn-domain',       source: 'asn', target: 'domain',       crossPivot: true, label: 'hosts_domain' }},
  { data: { id: 'asn-cloud_resource', source: 'asn', target: 'cloud_resource', crossPivot: true, label: 'hosts_cloud' }},

  // DNS Record
  { data: { id: 'dnsrec-domain',   source: 'dns_record', target: 'domain',   crossPivot: true, label: 'for_domain' }},
  { data: { id: 'dnsrec-ip',       source: 'dns_record', target: 'ip',       crossPivot: true, label: 'resolves_to' }},
  { data: { id: 'dnsrec-fqdn',     source: 'dns_record', target: 'fqdn',     crossPivot: true, label: 'for_fqdn' }},
  { data: { id: 'dnsrec-ssl_cert', source: 'dns_record', target: 'ssl_cert', crossPivot: true, label: 'cert_on_ip' }},

  // SSL Cert
  { data: { id: 'sslcert-domain',      source: 'ssl_cert', target: 'domain',      crossPivot: true, label: 'issued_to' }},
  { data: { id: 'sslcert-ip',          source: 'ssl_cert', target: 'ip',          crossPivot: true, label: 'observed_on' }},
  { data: { id: 'sslcert-ja3',         source: 'ssl_cert', target: 'ja3',         crossPivot: true, label: 'negotiated_by' }},
  { data: { id: 'sslcert-certificate', source: 'ssl_cert', target: 'certificate', crossPivot: true, label: 'chain_includes' }},

  // Certificate
  { data: { id: 'cert-ssl_cert',      source: 'certificate', target: 'ssl_cert',      crossPivot: true, label: 'in_chain' }},
  { data: { id: 'cert-domain',        source: 'certificate', target: 'domain',        crossPivot: true, label: 'issued_to' }},
  { data: { id: 'cert-ip',            source: 'certificate', target: 'ip',            crossPivot: true, label: 'observed_on' }},
  { data: { id: 'cert-cloud_resource',source: 'certificate', target: 'cloud_resource',crossPivot: true, label: 'used_by' }},

  // JA3
  { data: { id: 'ja3-ssl_cert',      source: 'ja3', target: 'ssl_cert',      crossPivot: true, label: 'negotiated' }},
  { data: { id: 'ja3-ip',            source: 'ja3', target: 'ip',            crossPivot: true, label: 'observed_from' }},
  { data: { id: 'ja3-user_agent',    source: 'ja3', target: 'user_agent',    crossPivot: true, label: 'correlated_ua' }},
  { data: { id: 'ja3-http_request',  source: 'ja3', target: 'http_request',  crossPivot: true, label: 'used_in' }},

  // User Agent
  { data: { id: 'ua-http_request', source: 'user_agent', target: 'http_request', crossPivot: true, label: 'seen_in' }},
  { data: { id: 'ua-url',          source: 'user_agent', target: 'url',          crossPivot: true, label: 'accessed' }},
  { data: { id: 'ua-process',      source: 'user_agent', target: 'process',      crossPivot: true, label: 'from_process' }},

  // Port
  { data: { id: 'port-ip',               source: 'port', target: 'ip',               crossPivot: true, label: 'open_on' }},
  { data: { id: 'port-service',          source: 'port', target: 'service',          crossPivot: true, label: 'runs_service' }},
  { data: { id: 'port-network_traffic',  source: 'port', target: 'network_traffic',  crossPivot: true, label: 'seen_in' }},
  { data: { id: 'port-vulnerability_id', source: 'port', target: 'vulnerability_id', crossPivot: true, label: 'has_vuln' }},

  // Service
  { data: { id: 'svc-port',            source: 'service', target: 'port',            crossPivot: true, label: 'listens_on' }},
  { data: { id: 'svc-host',            source: 'service', target: 'host',            crossPivot: true, label: 'runs_on' }},
  { data: { id: 'svc-process',         source: 'service', target: 'process',         crossPivot: true, label: 'backed_by' }},
  { data: { id: 'svc-vulnerability_id',source: 'service', target: 'vulnerability_id',crossPivot: true, label: 'has_vuln' }},
  { data: { id: 'svc-driver',          source: 'service', target: 'driver',          crossPivot: true, label: 'loads_driver' }},

  // Registry
  { data: { id: 'reg-process',        source: 'registry', target: 'process',        crossPivot: true, label: 'modified_by' }},
  { data: { id: 'reg-command_line',   source: 'registry', target: 'command_line',   crossPivot: true, label: 'contains_cmd' }},
  { data: { id: 'reg-scheduled_task', source: 'registry', target: 'scheduled_task', crossPivot: true, label: 'backs_task' }},
  { data: { id: 'reg-startup_item',   source: 'registry', target: 'startup_item',   crossPivot: true, label: 'backs_startup' }},
  { data: { id: 'reg-dll',            source: 'registry', target: 'dll',            crossPivot: true, label: 'references_dll' }},
  { data: { id: 'reg-driver',         source: 'registry', target: 'driver',         crossPivot: true, label: 'references_driver' }},

  // Scheduled Task
  { data: { id: 'task-command_line', source: 'scheduled_task', target: 'command_line', crossPivot: true, label: 'runs' }},
  { data: { id: 'task-process',      source: 'scheduled_task', target: 'process',      crossPivot: true, label: 'spawns' }},
  { data: { id: 'task-file_path',    source: 'scheduled_task', target: 'file_path',    crossPivot: true, label: 'references' }},
  { data: { id: 'task-user',         source: 'scheduled_task', target: 'user',         crossPivot: true, label: 'created_by' }},
  { data: { id: 'task-registry',     source: 'scheduled_task', target: 'registry',     crossPivot: true, label: 'backed_by' }},

  // Startup Item
  { data: { id: 'startup-file_path',  source: 'startup_item', target: 'file_path',  crossPivot: true, label: 'references' }},
  { data: { id: 'startup-registry',   source: 'startup_item', target: 'registry',   crossPivot: true, label: 'backed_by' }},
  { data: { id: 'startup-process',    source: 'startup_item', target: 'process',    crossPivot: true, label: 'launches' }},
  { data: { id: 'startup-dll',        source: 'startup_item', target: 'dll',        crossPivot: true, label: 'loads_dll' }},

  // DLL
  { data: { id: 'dll-process',    source: 'dll', target: 'process',    crossPivot: true, label: 'loaded_by' }},
  { data: { id: 'dll-file_path',  source: 'dll', target: 'file_path',  crossPivot: true, label: 'located_at' }},
  { data: { id: 'dll-hash',       source: 'dll', target: 'hash',       crossPivot: true, label: 'hashes_to' }},
  { data: { id: 'dll-driver',     source: 'dll', target: 'driver',     crossPivot: true, label: 'associated_driver' }},
  { data: { id: 'dll-mutex',      source: 'dll', target: 'mutex',      crossPivot: true, label: 'creates' }},

  // Mutex
  { data: { id: 'mutex-process', source: 'mutex', target: 'process', crossPivot: true, label: 'held_by' }},
  { data: { id: 'mutex-dll',     source: 'mutex', target: 'dll',     crossPivot: true, label: 'created_by' }},
  { data: { id: 'mutex-hash',    source: 'mutex', target: 'hash',    crossPivot: true, label: 'family_hash' }},

  // Pipe
  { data: { id: 'pipe-process', source: 'pipe', target: 'process', crossPivot: true, label: 'used_by' }},
  { data: { id: 'pipe-user',    source: 'pipe', target: 'user',    crossPivot: true, label: 'context' }},
  { data: { id: 'pipe-host',    source: 'pipe', target: 'host',    crossPivot: true, label: 'on_host' }},

  // Named Pipe
  { data: { id: 'npipe-process', source: 'named_pipe', target: 'process', crossPivot: true, label: 'used_by' }},
  { data: { id: 'npipe-user',    source: 'named_pipe', target: 'user',    crossPivot: true, label: 'context' }},
  { data: { id: 'npipe-host',    source: 'named_pipe', target: 'host',    crossPivot: true, label: 'on_host' }},
  { data: { id: 'npipe-dll',     source: 'named_pipe', target: 'dll',     crossPivot: true, label: 'injected_via' }},

  // Driver
  { data: { id: 'driver-file_path', source: 'driver', target: 'file_path', crossPivot: true, label: 'located_at' }},
  { data: { id: 'driver-hash',      source: 'driver', target: 'hash',      crossPivot: true, label: 'hashes_to' }},
  { data: { id: 'driver-service',   source: 'driver', target: 'service',   crossPivot: true, label: 'loaded_by' }},
  { data: { id: 'driver-process',   source: 'driver', target: 'process',   crossPivot: true, label: 'loaded_by' }},
  { data: { id: 'driver-dll',       source: 'driver', target: 'dll',       crossPivot: true, label: 'associated_dll' }},

  // Share
  { data: { id: 'share-host',      source: 'share', target: 'host',      crossPivot: true, label: 'hosted_on' }},
  { data: { id: 'share-ip',        source: 'share', target: 'ip',        crossPivot: true, label: 'accessible_via' }},
  { data: { id: 'share-user',      source: 'share', target: 'user',      crossPivot: true, label: 'accessed_by' }},
  { data: { id: 'share-file_path', source: 'share', target: 'file_path', crossPivot: true, label: 'contains' }},

  // RDP Session
  { data: { id: 'rdp-host',     source: 'rdp_session', target: 'host',     crossPivot: true, label: 'targets' }},
  { data: { id: 'rdp-ip',       source: 'rdp_session', target: 'ip',       crossPivot: true, label: 'from_ip' }},
  { data: { id: 'rdp-user',     source: 'rdp_session', target: 'user',     crossPivot: true, label: 'initiated_by' }},
  { data: { id: 'rdp-event_id', source: 'rdp_session', target: 'event_id', crossPivot: true, label: 'logged_as' }},

  // Cloud Resource
  { data: { id: 'cloud-ip',               source: 'cloud_resource', target: 'ip',               crossPivot: true, label: 'accessed_from' }},
  { data: { id: 'cloud-user',             source: 'cloud_resource', target: 'user',             crossPivot: true, label: 'accessed_by' }},
  { data: { id: 'cloud-identity',         source: 'cloud_resource', target: 'identity',         crossPivot: true, label: 'via_identity' }},
  { data: { id: 'cloud-asn',              source: 'cloud_resource', target: 'asn',              crossPivot: true, label: 'hosted_in' }},
  { data: { id: 'cloud-service',          source: 'cloud_resource', target: 'service',          crossPivot: true, label: 'backs_service' }},
  { data: { id: 'cloud-vulnerability_id', source: 'cloud_resource', target: 'vulnerability_id', crossPivot: true, label: 'has_vuln' }},

  // Event ID
  { data: { id: 'evtid-process',  source: 'event_id', target: 'process',  crossPivot: true, label: 'logs_process' }},
  { data: { id: 'evtid-user',     source: 'event_id', target: 'user',     crossPivot: true, label: 'logs_user' }},
  { data: { id: 'evtid-host',     source: 'event_id', target: 'host',     crossPivot: true, label: 'logs_on' }},
  { data: { id: 'evtid-registry', source: 'event_id', target: 'registry', crossPivot: true, label: 'logs_registry' }},

  // MAC Address
  { data: { id: 'mac-host', source: 'mac_address', target: 'host', crossPivot: true, label: 'belongs_to' }},
  { data: { id: 'mac-ip',   source: 'mac_address', target: 'ip',   crossPivot: true, label: 'assigned_ip' }},

  // Vulnerability ID
  { data: { id: 'vuln-host',           source: 'vulnerability_id', target: 'host',           crossPivot: true, label: 'affects' }},
  { data: { id: 'vuln-service',        source: 'vulnerability_id', target: 'service',        crossPivot: true, label: 'in_service' }},
  { data: { id: 'vuln-cloud_resource', source: 'vulnerability_id', target: 'cloud_resource', crossPivot: true, label: 'in_cloud' }},
  { data: { id: 'vuln-port',           source: 'vulnerability_id', target: 'port',           crossPivot: true, label: 'via_port' }},

  // Network Traffic
  { data: { id: 'nettraffic-ip',         source: 'network_traffic', target: 'ip',         crossPivot: true, label: 'involves_ip' }},
  { data: { id: 'nettraffic-port',       source: 'network_traffic', target: 'port',       crossPivot: true, label: 'on_port' }},
  { data: { id: 'nettraffic-service',    source: 'network_traffic', target: 'service',    crossPivot: true, label: 'to_service' }},
  { data: { id: 'nettraffic-user_agent', source: 'network_traffic', target: 'user_agent', crossPivot: true, label: 'carries_ua' }},
  { data: { id: 'nettraffic-ja3',        source: 'network_traffic', target: 'ja3',        crossPivot: true, label: 'fingerprint' }},

  // WMI Query
  { data: { id: 'wmi-process',        source: 'wmi_query', target: 'process',        crossPivot: true, label: 'issued_by' }},
  { data: { id: 'wmi-user',           source: 'wmi_query', target: 'user',           crossPivot: true, label: 'run_by' }},
  { data: { id: 'wmi-command_line',   source: 'wmi_query', target: 'command_line',   crossPivot: true, label: 'contains' }},
  { data: { id: 'wmi-scheduled_task', source: 'wmi_query', target: 'scheduled_task', crossPivot: true, label: 'creates' }},
  { data: { id: 'wmi-registry',       source: 'wmi_query', target: 'registry',       crossPivot: true, label: 'persists_via' }},

  // Prefetch
  { data: { id: 'prefetch-file_path', source: 'prefetch', target: 'file_path', crossPivot: true, label: 'records_exec' }},
  { data: { id: 'prefetch-process',   source: 'prefetch', target: 'process',   crossPivot: true, label: 'proves_ran' }},
  { data: { id: 'prefetch-hash',      source: 'prefetch', target: 'hash',      crossPivot: true, label: 'binary_hash' }},
  { data: { id: 'prefetch-dll',       source: 'prefetch', target: 'dll',       crossPivot: true, label: 'loaded_dlls' }}
];

// ── ARTIFACT_PATHS — programmatic from GRAPH_EDGES ────────────────────────
const ARTIFACT_PATHS = {};
(function () {
  var MITRE_INFO = {
    ip: 'T1071.001 · T1090 · T1046 · T1016',
    domain: 'T1071 · T1566.002 · T1190 · T1584.001',
    fqdn: 'T1071 · T1568',
    url: 'T1566.002 · T1204.001 · T1071.001',
    dns_query: 'T1071.004 · T1568 · T1048.003',
    http_request: 'T1071.001 · T1105 · T1041',
    asn: 'T1090 · T1584.003',
    dns_record: 'T1584.001 · T1071.004',
    ssl_cert: 'T1553.004 · T1584 · T1090.002',
    ja3: 'T1071.001 · T1573',
    user_agent: 'T1071.001 · T1218',
    port: 'T1046 · T1571',
    certificate: 'T1553.002 · T1036.001',
    network_traffic: 'T1040 · T1046 · T1071',
    mac_address: 'T1016 · T1049',
    hash: 'T1027 · T1064 · T1204.002 · T1059',
    file_path: 'T1074 · T1083 · T1036.005',
    process: 'T1059 · T1055 · T1003 · T1218 · T1071',
    parent_process: 'T1055 · T1134 · T1059',
    command_line: 'T1059 · T1027.010 · T1218',
    service: 'T1543.003 · T1050 · T1021.002',
    registry: 'T1547.001 · T1112',
    scheduled_task: 'T1053.005 · T1053',
    startup_item: 'T1547 · T1037',
    dll: 'T1574.001 · T1574.002 · T1129',
    mutex: 'T1480 · T1622',
    pipe: 'T1559.001 · T1021.002',
    driver: 'T1014 · T1547.006 · T1068',
    host: 'T1018 · T1082 · T1016',
    share: 'T1021.002 · T1039 · T1074',
    event_id: 'T1562.002 · T1070.001',
    named_pipe: 'T1559.001 · T1021.002',
    wmi_query: 'T1047 · T1546.003',
    prefetch: 'T1083 · T1027',
    vulnerability_id: 'T1190 · T1068 · T1203',
    user: 'T1078 · T1087 · T1021',
    identity: 'T1078.004 · T1136.003 · T1098',
    rdp_session: 'T1021.001 · T1563.002',
    email: 'T1566.001 · T1566.002 · T1598',
    attachment: 'T1566.001 · T1204.002 · T1027',
    cloud_resource: 'T1078.004 · T1537 · T1530 · T1619'
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
