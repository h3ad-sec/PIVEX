// PIVEX — graph-data.js  v10.0
// 36 artifact nodes + directed edges

const GRAPH_NODES = [
  // ── ARTIFACT NODES — Network (14) ────────────────────────────────────────
  { data: { id: 'ip', type: 'artifact', category: 'network', label: 'IP Address',
      desc: 'IPv4/IPv6 address observed in logs, alerts, or network telemetry.',
      sources: 'Firewall · SIEM · NetFlow · Proxy · EDR',
      pivots: ['Domain (resolves_to)', 'FQDN (resolves_to)', 'URL (hosts)', 'Network Session (communicates_with)', 'SSL Certificate (presents)', 'Network Traffic (observed_in)', 'ASN (belongs_to)', 'Port (has_open_port)'],
      mitre: 'T1071.001 · T1090 · T1046 · T1016' }},
  { data: { id: 'domain', type: 'artifact', category: 'network', label: 'Domain',
      desc: 'Domain name seen in DNS queries, HTTP traffic, or email headers.',
      sources: 'DNS logs · Proxy · Email Gateway · Passive DNS',
      pivots: ['IP (resolves_to)', 'FQDN (parent_of)', 'URL (hosts)', 'SSL Certificate (uses)', 'Email (used_in)', 'ASN (registered_under)'],
      mitre: 'T1071 · T1566.002 · T1190 · T1584.001' }},
  { data: { id: 'fqdn', type: 'artifact', category: 'network', label: 'FQDN',
      desc: 'Fully qualified domain name: precise subdomain used in C2 or delivery.',
      sources: 'DNS logs · Proxy · EDR · Sysmon Event 22',
      pivots: ['Domain (belongs_to)', 'IP (resolves_to)', 'URL (hosts)', 'SSL Certificate (uses)'],
      mitre: 'T1071 · T1568' }},
  { data: { id: 'url', type: 'artifact', category: 'network', label: 'URL',
      desc: 'Full URL from proxy, email links, or browser history.',
      sources: 'Proxy logs · Email Gateway · Browser history · EDR',
      pivots: ['Domain (belongs_to)', 'FQDN (belongs_to)', 'IP (connects_to)', 'HTTP Request (requested_via)', 'File (delivers)', 'User Agent (accessed_by)', 'Email (embedded_in)'],
      mitre: 'T1566.002 · T1204.001 · T1071.001' }},
  { data: { id: 'dns_query', type: 'artifact', category: 'network', label: 'DNS Query',
      desc: 'DNS resolution request: reveals C2 beaconing, DGA, and exfil patterns.',
      sources: 'DNS logs · Sysmon Event 22 · EDR · Network tap',
      pivots: ['Domain (queries)', 'FQDN (queries)', 'IP (resolves_to)', 'Host (initiated_by)', 'Process (issued_by)'],
      mitre: 'T1071.004 · T1568 · T1048.003' }},
  { data: { id: 'http_request', type: 'artifact', category: 'network', label: 'HTTP Request',
      desc: 'HTTP/S request with method, headers, user-agent, and response.',
      sources: 'Proxy · Firewall · EDR · Zeek / Suricata · Network sensor',
      pivots: ['URL (targets)', 'User Agent (uses)', 'Process (from_process)'],
      mitre: 'T1071.001 · T1105 · T1041' }},
  { data: { id: 'ssl_cert', type: 'artifact', category: 'network', label: 'SSL Cert',
      desc: 'SSL/TLS certificate fingerprint (SHA1/SHA256 thumbprint): quick infrastructure pivot.',
      sources: 'Censys · Shodan · crt.sh · JARM · Passive DNS',
      pivots: ['SSL Certificate (expands_to)', 'Domain (associated_with)', 'IP (associated_with)'],
      mitre: 'T1553.004 · T1584' }},
  { data: { id: 'ssl_certificate', type: 'artifact', category: 'network', label: 'SSL Certificate',
      desc: 'Full SSL/TLS certificate: serial, CN, SAN, strong infrastructure clustering.',
      sources: 'Censys · Shodan · crt.sh · JARM · Passive DNS',
      pivots: ['Domain (issued_to)', 'IP (used_by)'],
      mitre: 'T1553.004 · T1584 · T1090.002' }},
  { data: { id: 'ja3', type: 'artifact', category: 'network', label: 'JA3 Hash',
      desc: 'TLS client fingerprint: identifies malware TLS implementation uniquely.',
      sources: 'Network sensor · Zeek · Suricata · PCAP',
      pivots: ['IP (observed_on)', 'Domain (connects_to)', 'SSL Certificate (observed_with)', 'Hash (associated_with)'],
      mitre: 'T1071.001 · T1573' }},
  { data: { id: 'user_agent', type: 'artifact', category: 'network', label: 'User Agent',
      desc: 'HTTP User-Agent string: identifies tool, framework, or spoofed browser.',
      sources: 'Proxy · Zeek · Firewall · SIEM',
      pivots: ['URL (accesses)', 'IP (observed_from)', 'Network Session (part_of)', 'Host (originates_from)'],
      mitre: 'T1071.001 · T1218' }},
  { data: { id: 'network_traffic', type: 'artifact', category: 'network', label: 'Net Traffic',
      desc: 'NetFlow/PCAP session record: port, protocol, volume, and timing metadata.',
      sources: 'NetFlow · Zeek · Suricata · PCAP · Firewall · Network sensor',
      pivots: ['IP (involves)', 'Domain (involves)', 'Host (involves)', 'Port (uses)', 'Network Session (part_of)'],
      mitre: 'T1040 · T1046 · T1071' }},
  { data: { id: 'network_session', type: 'artifact', category: 'network', label: 'Net Session',
      desc: 'Network session: source/destination IPs, domain contacted, URL accessed.',
      sources: 'NetFlow · Firewall · Proxy · Zeek · EDR',
      pivots: ['IP (originates_from / connects_to)', 'Domain (queries)', 'URL (accesses)', 'Host (involves)', 'Process (initiated_by)'],
      mitre: 'T1071.001 · T1071.004 · T1048' }},
  { data: { id: 'asn', type: 'artifact', category: 'network', label: 'ASN',
      desc: 'Autonomous System Number: bulk IP attribution and threat actor infrastructure clustering.',
      sources: 'WHOIS · Shodan · Censys · BGP · ipinfo.io · VirusTotal',
      pivots: ['IP (contains)', 'Domain (registered_under)'],
      mitre: 'T1583.003 · T1584.003 · T1590.005' }},
  { data: { id: 'port', type: 'artifact', category: 'network', label: 'Port',
      desc: 'TCP/UDP port number: exposed services, scanning targets, and non-standard C2 channels.',
      sources: 'Shodan · Censys · Nmap · Firewall logs · NetFlow · Zeek',
      pivots: ['IP (open_on)', 'Host (open_on)', 'Network Session (part_of)', 'Service (exposes)'],
      mitre: 'T1046 · T1571 · T1205' }},

  // ── ARTIFACT NODES: Endpoint (18) ───────────────────────────────────────
  { data: { id: 'hash', type: 'artifact', category: 'endpoint', label: 'File Hash',
      desc: 'MD5/SHA1/SHA256 of a file on disk, in memory, or from email attachment.',
      sources: 'EDR · AV · Sandbox · MalwareBazaar · Email scan',
      pivots: ['File (identifies)', 'URL (downloaded_from)', 'IP (hosted_on)', 'Domain (associated_with)', 'Process (executed_by)'],
      mitre: 'T1027 · T1064 · T1204.002 · T1059' }},
  { data: { id: 'file', type: 'artifact', category: 'endpoint', label: 'File',
      desc: 'Binary, script, document, or any on-disk file artifact.',
      sources: 'EDR · Sandbox · AV · MalwareBazaar · File system audit',
      pivots: ['Hash (has_hash)', 'Process (executed_by / spawned_by)', 'Host (exists_on)', 'User (owned_by)', 'URL (downloaded_from)'],
      mitre: 'T1027 · T1204.002 · T1059 · T1083' }},
  { data: { id: 'file_path', type: 'artifact', category: 'endpoint', label: 'File Path',
      desc: 'File / directory path: drop locations, staging dirs, LOLBin paths.',
      sources: 'EDR · Sysmon Event 11 · Windows Security · MFT · USN Journal',
      pivots: ['File (points_to)', 'Host (located_on)', 'Process (executed_from)'],
      mitre: 'T1074 · T1083 · T1036.005' }},
  { data: { id: 'process', type: 'artifact', category: 'endpoint', label: 'Process',
      desc: 'Running or historical process: command line, spawns, registry writes, and network activity.',
      sources: 'EDR · Sysmon Event 1 · WinEvent 4688 · Process Monitor',
      pivots: ['Registry (modifies)', 'Scheduled Task (creates)', 'Startup Item (creates)', 'Process (spawned_by / spawns)', 'Command Line (executed_with)', 'File (runs)', 'User (executed_as)', 'Host (runs_on)', 'Network Session (initiates)', 'IP (connects_to)', 'Domain (contacts)', 'DNS Query (issues)', 'Hash (has_image)', 'DLL (loads)', 'Named Pipe (creates)', 'Mutex (creates)', 'Service (creates)'],
      mitre: 'T1059 · T1055 · T1003 · T1218 · T1071' }},
  { data: { id: 'command_line', type: 'artifact', category: 'endpoint', label: 'Command Line',
      desc: 'Full command-line string: LOLBin abuse, encoded payloads, script execution.',
      sources: 'EDR · Sysmon Event 1 · WinEvent 4688 · PowerShell logs · ScriptBlock',
      pivots: ['Process (used_by)', 'File (drops)', 'URL (contains)', 'IP (connects_to)'],
      mitre: 'T1059 · T1027.010 · T1218' }},
  { data: { id: 'registry', type: 'artifact', category: 'endpoint', label: 'Registry Key',
      desc: 'Windows registry key/value: persistence, configuration, and malware indicators.',
      sources: 'Sysmon 12/13/14 · EDR · WinEvent 4657 · Autoruns · reg.exe',
      pivots: ['Host (exists_on)', 'File (points_to)', 'Process (runs)'],
      mitre: 'T1547.001 · T1112' }},
  { data: { id: 'scheduled_task', type: 'artifact', category: 'endpoint', label: 'Sched. Task',
      desc: 'Windows scheduled task: persistence and lateral execution mechanism.',
      sources: 'Sysmon Event 11 · EDR · Task Scheduler logs · WinEvent 4698',
      pivots: ['Host (runs_on)', 'Process (executes)', 'File (runs)', 'Command Line (executes)', 'User (runs_as)'],
      mitre: 'T1053.005 · T1053' }},
  { data: { id: 'startup_item', type: 'artifact', category: 'endpoint', label: 'Startup Item',
      desc: 'Startup folder, run key, or IFEO entry: persistent execution after reboot.',
      sources: 'Autoruns · EDR · Sysmon · Registry audit · WinEvent 4688',
      pivots: ['Host (runs_on)', 'File (points_to)', 'Process (executes)'],
      mitre: 'T1547 · T1037' }},
  { data: { id: 'host', type: 'artifact', category: 'endpoint', label: 'Host',
      desc: 'Endpoint, server, or workstation involved in the incident.',
      sources: 'EDR · SIEM · AD · Vuln Scanner · CMDB',
      pivots: ['Process (runs)', 'File (stores)', 'User (used_by)', 'IP (assigned)', 'Network Session (generates)', 'Vulnerability ID (has_vulnerability)', 'RDP Session (receives)', 'Scheduled Task (has_task)', 'Registry (has_key)', 'Service (runs)', 'Port (has_open_port)'],
      mitre: 'T1018 · T1082 · T1016' }},
  { data: { id: 'share', type: 'artifact', category: 'endpoint', label: 'Network Share',
      desc: 'SMB/NFS share: lateral movement staging, data collection, exfil path.',
      sources: 'WinEvent 5140/5145 · EDR · Sysmon · Network traffic · AD',
      pivots: ['Host (hosted_on)', 'User (accessed_by)', 'File (contains)'],
      mitre: 'T1021.002 · T1039 · T1074' }},
  { data: { id: 'event_id', type: 'artifact', category: 'endpoint', label: 'Event ID',
      desc: 'Windows Event ID: specific log event correlating process, user, or host.',
      sources: 'Windows Event Log · SIEM · Splunk · Elastic',
      pivots: ['Process (relates_to)', 'Host (occurs_on)', 'User (involves)'],
      mitre: 'T1562.002 · T1070.001' }},
  { data: { id: 'vulnerability_id', type: 'artifact', category: 'endpoint', label: 'Vuln ID',
      desc: 'CVE / vulnerability identifier: links exploit activity to host.',
      sources: 'NVD · CISA KEV · Tenable · Qualys · Shodan · EDR',
      pivots: ['Host (affects)', 'Process (exploited_by)', 'Service (targets)'],
      mitre: 'T1190 · T1068 · T1203' }},
  { data: { id: 'service', type: 'artifact', category: 'endpoint', label: 'Service',
      desc: 'Windows/Linux service: persistence, privilege escalation, and lateral movement vector.',
      sources: 'EDR · Sysmon Event 4697 · WinEvent 7045 · SC · Autoruns',
      pivots: ['Process (runs)', 'Host (registered_on)', 'File (executes)'],
      mitre: 'T1543.003 · T1569.002 · T1035' }},
  { data: { id: 'mutex', type: 'artifact', category: 'endpoint', label: 'Mutex',
      desc: 'Named mutex: strong malware family marker; same mutex across hosts confirms campaign scope.',
      sources: 'EDR · Sandbox · Process Monitor · Sysmon · Volatility · MalwareBazaar',
      pivots: ['Process (created_by)', 'Host (observed_on)', 'Hash (associated_with)'],
      mitre: 'T1480 · T1106' }},
  { data: { id: 'named_pipe', type: 'artifact', category: 'endpoint', label: 'Named Pipe',
      desc: 'Windows named pipe: used by Cobalt Strike, RATs, and lateral movement tools for IPC.',
      sources: 'EDR · Sysmon Event 17/18 · Process Monitor · Volatility',
      pivots: ['Process (created_by)', 'Host (observed_on)'],
      mitre: 'T1021.002 · T1559.001 · T1090' }},
  { data: { id: 'dll', type: 'artifact', category: 'endpoint', label: 'DLL',
      desc: 'Dynamic-link library: hijacking, side-loading, reflective injection, and search-order abuse.',
      sources: 'EDR · Sysmon Event 7 · Process Monitor · Autoruns · PE analysis',
      pivots: ['Process (loaded_by)', 'Host (exists_on)', 'Hash (has_hash)', 'File (is_file)'],
      mitre: 'T1574.001 · T1574.002 · T1055.001' }},

  // ── ARTIFACT NODES: Identity (3) ────────────────────────────────────────
  { data: { id: 'user', type: 'artifact', category: 'identity', label: 'User',
      desc: 'User account: local, domain, or service account involved in the activity.',
      sources: 'AD logs · IAM · Okta · SIEM · UEBA',
      pivots: ['Host (logs_into)', 'Process (executes)', 'IP (originates_from)', 'Cloud Resource (accesses)', 'Email (sends / receives)', 'Identity (mapped_to)', 'Share (accesses)'],
      mitre: 'T1078 · T1087 · T1021' }},
  { data: { id: 'identity', type: 'artifact', category: 'identity', label: 'Identity',
      desc: 'Cloud / federated identity: Azure AD, AWS IAM, GCP SA, cloud access vector.',
      sources: 'Azure AD · AWS IAM · GCP SA · Okta · SIEM · CloudTrail',
      pivots: ['User (represents)', 'Cloud Resource (accesses)', 'IP (originates_from)'],
      mitre: 'T1078.004 · T1136.003 · T1098' }},
  { data: { id: 'rdp_session', type: 'artifact', category: 'identity', label: 'RDP Session',
      desc: 'RDP session: lateral movement, credential exposure, remote access.',
      sources: 'WinEvent 4624/4778/4779 · EDR · NetFlow · Security Onion',
      pivots: ['Host (connects_to)', 'User (initiated_by)', 'IP (from_ip)', 'Network Session (part_of)'],
      mitre: 'T1021.001 · T1563.002' }},

  // ── ARTIFACT NODES: Email (2) ────────────────────────────────────────────
  { data: { id: 'email', type: 'artifact', category: 'email', label: 'Email',
      desc: 'Phishing or suspicious email: headers, body, embedded URLs, attachments.',
      sources: 'Email Gateway · O365 Message Trace · SIEM · Proofpoint · Mimecast',
      pivots: ['Attachment (contains)', 'URL (contains)', 'Domain (originates_from)', 'IP (originates_from)', 'User (sent_to)'],
      mitre: 'T1566.001 · T1566.002 · T1598' }},
  { data: { id: 'attachment', type: 'artifact', category: 'email', label: 'Attachment',
      desc: 'Email attachment: document with macro, PE dropper, or archive payload.',
      sources: 'Email Gateway · Sandbox · AV · EDR · O365 ATP',
      pivots: ['Hash (has_hash)', 'File (delivers)', 'URL (contains)', 'Process (spawns)'],
      mitre: 'T1566.001 · T1204.002 · T1027' }},

  // ── ARTIFACT NODES — Cloud (1) ────────────────────────────────────────────
  { data: { id: 'cloud_resource', type: 'artifact', category: 'cloud', label: 'Cloud Resource',
      desc: 'S3 bucket, Azure blob, IAM role, Lambda, or cloud compute resource.',
      sources: 'CloudTrail · Azure Monitor · GCP Audit · GuardDuty · Defender for Cloud',
      pivots: ['Identity (owned_by)', 'IP (exposed_via)', 'User (accessed_by)'],
      mitre: 'T1078.004 · T1537 · T1530 · T1619' }}
];

const GRAPH_EDGES = [
  // ── IP ────────────────────────────────────────────────────────────────────
  { data: { id: 'ip-domain',              source: 'ip',             target: 'domain',           crossPivot: true, label: 'resolves_to' }},
  { data: { id: 'ip-fqdn',                source: 'ip',             target: 'fqdn',             crossPivot: true, label: 'resolves_to' }},
  { data: { id: 'ip-url',                 source: 'ip',             target: 'url',              crossPivot: true, label: 'hosts' }},
  { data: { id: 'ip-network_session',     source: 'ip',             target: 'network_session',  crossPivot: true, label: 'communicates_with' }},
  { data: { id: 'ip-ssl_certificate',     source: 'ip',             target: 'ssl_certificate',  crossPivot: true, label: 'presents' }},
  { data: { id: 'ip-network_traffic',     source: 'ip',             target: 'network_traffic',  crossPivot: true, label: 'observed_in' }},
  { data: { id: 'ip-asn',                 source: 'ip',             target: 'asn',              crossPivot: true, label: 'belongs_to' }},
  { data: { id: 'ip-port',                source: 'ip',             target: 'port',             crossPivot: true, label: 'has_open_port' }},

  // ── Domain ────────────────────────────────────────────────────────────────
  { data: { id: 'domain-ip',              source: 'domain',         target: 'ip',               crossPivot: true, label: 'resolves_to' }},
  { data: { id: 'domain-fqdn',            source: 'domain',         target: 'fqdn',             crossPivot: true, label: 'parent_of' }},
  { data: { id: 'domain-url',             source: 'domain',         target: 'url',              crossPivot: true, label: 'hosts' }},
  { data: { id: 'domain-sslcertificate',  source: 'domain',         target: 'ssl_certificate',  crossPivot: true, label: 'uses' }},
  { data: { id: 'domain-email',           source: 'domain',         target: 'email',            crossPivot: true, label: 'used_in' }},
  { data: { id: 'domain-asn',             source: 'domain',         target: 'asn',              crossPivot: true, label: 'registered_under' }},

  // ── FQDN ─────────────────────────────────────────────────────────────────
  { data: { id: 'fqdn-domain',            source: 'fqdn',           target: 'domain',           crossPivot: true, label: 'belongs_to' }},
  { data: { id: 'fqdn-ip',                source: 'fqdn',           target: 'ip',               crossPivot: true, label: 'resolves_to' }},
  { data: { id: 'fqdn-url',               source: 'fqdn',           target: 'url',              crossPivot: true, label: 'hosts' }},
  { data: { id: 'fqdn-sslcert',           source: 'fqdn',           target: 'ssl_certificate',  crossPivot: true, label: 'uses' }},

  // ── URL ──────────────────────────────────────────────────────────────────
  { data: { id: 'url-domain',             source: 'url',            target: 'domain',           crossPivot: true, label: 'belongs_to' }},
  { data: { id: 'url-fqdn',               source: 'url',            target: 'fqdn',             crossPivot: true, label: 'belongs_to' }},
  { data: { id: 'url-ip',                 source: 'url',            target: 'ip',               crossPivot: true, label: 'connects_to' }},
  { data: { id: 'url-http_request',       source: 'url',            target: 'http_request',     crossPivot: true, label: 'requested_via' }},
  { data: { id: 'url-file',               source: 'url',            target: 'file',             crossPivot: true, label: 'delivers' }},
  { data: { id: 'url-user_agent',         source: 'url',            target: 'user_agent',       crossPivot: true, label: 'accessed_by' }},
  { data: { id: 'url-email',              source: 'url',            target: 'email',            crossPivot: true, label: 'embedded_in' }},

  // ── DNS Query ─────────────────────────────────────────────────────────────
  { data: { id: 'dnsq-domain',            source: 'dns_query',      target: 'domain',           crossPivot: true, label: 'queries' }},
  { data: { id: 'dnsq-fqdn',              source: 'dns_query',      target: 'fqdn',             crossPivot: true, label: 'queries' }},
  { data: { id: 'dnsq-ip',                source: 'dns_query',      target: 'ip',               crossPivot: true, label: 'resolves_to' }},
  { data: { id: 'dnsq-host',              source: 'dns_query',      target: 'host',             crossPivot: true, label: 'initiated_by' }},
  { data: { id: 'dnsq-process',           source: 'dns_query',      target: 'process',          crossPivot: true, label: 'issued_by' }},

  // ── HTTP Request ──────────────────────────────────────────────────────────
  { data: { id: 'httpreq-url',            source: 'http_request',   target: 'url',              crossPivot: true, label: 'targets' }},
  { data: { id: 'httpreq-ua',             source: 'http_request',   target: 'user_agent',       crossPivot: true, label: 'uses' }},
  { data: { id: 'httpreq-process',        source: 'http_request',   target: 'process',          crossPivot: true, label: 'from_process' }},

  // ── SSL Cert (fingerprint) ────────────────────────────────────────────────
  { data: { id: 'sslcert-full',           source: 'ssl_cert',       target: 'ssl_certificate',  crossPivot: true, label: 'expands_to' }},
  { data: { id: 'sslcert-domain',         source: 'ssl_cert',       target: 'domain',           crossPivot: true, label: 'associated_with' }},
  { data: { id: 'sslcert-ip',             source: 'ssl_cert',       target: 'ip',               crossPivot: true, label: 'associated_with' }},

  // ── SSL Certificate (full) ────────────────────────────────────────────────
  { data: { id: 'sslcertfull-domain',     source: 'ssl_certificate', target: 'domain',          crossPivot: true, label: 'issued_to' }},
  { data: { id: 'sslcertfull-ip',         source: 'ssl_certificate', target: 'ip',              crossPivot: true, label: 'used_by' }},

  // ── JA3 ──────────────────────────────────────────────────────────────────
  { data: { id: 'ja3-ip',                 source: 'ja3',            target: 'ip',               crossPivot: true, label: 'observed_on' }},
  { data: { id: 'ja3-domain',             source: 'ja3',            target: 'domain',           crossPivot: true, label: 'connects_to' }},
  { data: { id: 'ja3-sslcert',            source: 'ja3',            target: 'ssl_certificate',  crossPivot: true, label: 'observed_with' }},
  { data: { id: 'ja3-hash',               source: 'ja3',            target: 'hash',             crossPivot: true, label: 'associated_with' }},

  // ── User Agent ───────────────────────────────────────────────────────────
  { data: { id: 'ua-url',                 source: 'user_agent',     target: 'url',              crossPivot: true, label: 'accesses' }},
  { data: { id: 'ua-ip',                  source: 'user_agent',     target: 'ip',               crossPivot: true, label: 'observed_from' }},
  { data: { id: 'ua-network_session',     source: 'user_agent',     target: 'network_session',  crossPivot: true, label: 'part_of' }},
  { data: { id: 'ua-host',                source: 'user_agent',     target: 'host',             crossPivot: true, label: 'originates_from' }},

  // ── Network Traffic ──────────────────────────────────────────────────────
  { data: { id: 'nettraffic-ip',          source: 'network_traffic', target: 'ip',              crossPivot: true, label: 'involves' }},
  { data: { id: 'nettraffic-domain',      source: 'network_traffic', target: 'domain',          crossPivot: true, label: 'involves' }},
  { data: { id: 'nettraffic-host',        source: 'network_traffic', target: 'host',            crossPivot: true, label: 'involves' }},
  { data: { id: 'nettraffic-port',        source: 'network_traffic', target: 'port',            crossPivot: true, label: 'uses' }},
  { data: { id: 'nettraffic-netsess',     source: 'network_traffic', target: 'network_session', crossPivot: true, label: 'part_of' }},

  // ── Network Session ──────────────────────────────────────────────────────
  { data: { id: 'netsess-ip-from',        source: 'network_session', target: 'ip',              crossPivot: true, label: 'originates_from' }},
  { data: { id: 'netsess-ip-to',          source: 'network_session', target: 'ip',              crossPivot: true, label: 'connects_to' }},
  { data: { id: 'netsess-domain',         source: 'network_session', target: 'domain',          crossPivot: true, label: 'queries' }},
  { data: { id: 'netsess-url',            source: 'network_session', target: 'url',             crossPivot: true, label: 'accesses' }},
  { data: { id: 'netsess-host',           source: 'network_session', target: 'host',            crossPivot: true, label: 'involves' }},
  { data: { id: 'netsess-process',        source: 'network_session', target: 'process',         crossPivot: true, label: 'initiated_by' }},

  // ── ASN ──────────────────────────────────────────────────────────────────
  { data: { id: 'asn-ip',                 source: 'asn',            target: 'ip',               crossPivot: true, label: 'contains' }},
  { data: { id: 'asn-domain',             source: 'asn',            target: 'domain',           crossPivot: true, label: 'registered_under' }},

  // ── Port ─────────────────────────────────────────────────────────────────
  { data: { id: 'port-ip',                source: 'port',           target: 'ip',               crossPivot: true, label: 'open_on' }},
  { data: { id: 'port-host',              source: 'port',           target: 'host',             crossPivot: true, label: 'open_on' }},
  { data: { id: 'port-netsess',           source: 'port',           target: 'network_session',  crossPivot: true, label: 'part_of' }},
  { data: { id: 'port-service',           source: 'port',           target: 'service',          crossPivot: true, label: 'exposes' }},

  // ── Hash ─────────────────────────────────────────────────────────────────
  { data: { id: 'hash-file',              source: 'hash',           target: 'file',             crossPivot: true, label: 'identifies' }},
  { data: { id: 'hash-url',               source: 'hash',           target: 'url',              crossPivot: true, label: 'downloaded_from' }},
  { data: { id: 'hash-ip',                source: 'hash',           target: 'ip',               crossPivot: true, label: 'hosted_on' }},
  { data: { id: 'hash-domain',            source: 'hash',           target: 'domain',           crossPivot: true, label: 'associated_with' }},
  { data: { id: 'hash-process',           source: 'hash',           target: 'process',          crossPivot: true, label: 'executed_by' }},

  // ── File ─────────────────────────────────────────────────────────────────
  { data: { id: 'file-hash',              source: 'file',           target: 'hash',             crossPivot: true, label: 'has_hash' }},
  { data: { id: 'file-process-exec',      source: 'file',           target: 'process',          crossPivot: true, label: 'executed_by' }},
  { data: { id: 'file-process-spawn',     source: 'file',           target: 'process',          crossPivot: true, label: 'spawned_by' }},
  { data: { id: 'file-host',              source: 'file',           target: 'host',             crossPivot: true, label: 'exists_on' }},
  { data: { id: 'file-user',              source: 'file',           target: 'user',             crossPivot: true, label: 'owned_by' }},
  { data: { id: 'file-url',               source: 'file',           target: 'url',              crossPivot: true, label: 'downloaded_from' }},

  // ── File Path ────────────────────────────────────────────────────────────
  { data: { id: 'filepath-file',          source: 'file_path',      target: 'file',             crossPivot: true, label: 'points_to' }},
  { data: { id: 'filepath-host',          source: 'file_path',      target: 'host',             crossPivot: true, label: 'located_on' }},
  { data: { id: 'filepath-process',       source: 'file_path',      target: 'process',          crossPivot: true, label: 'executed_from' }},

  // ── Process ──────────────────────────────────────────────────────────────
  { data: { id: 'proc-registry',          source: 'process',        target: 'registry',         crossPivot: true, label: 'modifies' }},
  { data: { id: 'proc-scheduled_task',    source: 'process',        target: 'scheduled_task',   crossPivot: true, label: 'creates' }},
  { data: { id: 'proc-startup_item',      source: 'process',        target: 'startup_item',     crossPivot: true, label: 'creates' }},
  { data: { id: 'proc-proc-spawned',      source: 'process',        target: 'process',          crossPivot: true, label: 'spawned_by' }},
  { data: { id: 'proc-proc-spawns',       source: 'process',        target: 'process',          crossPivot: true, label: 'spawns' }},
  { data: { id: 'proc-command_line',      source: 'process',        target: 'command_line',     crossPivot: true, label: 'executed_with' }},
  { data: { id: 'proc-file',              source: 'process',        target: 'file',             crossPivot: true, label: 'runs' }},
  { data: { id: 'proc-user',              source: 'process',        target: 'user',             crossPivot: true, label: 'executed_as' }},
  { data: { id: 'proc-host',              source: 'process',        target: 'host',             crossPivot: true, label: 'runs_on' }},
  { data: { id: 'proc-network_session',   source: 'process',        target: 'network_session',  crossPivot: true, label: 'initiates' }},
  { data: { id: 'proc-ip',                source: 'process',        target: 'ip',               crossPivot: true, label: 'connects_to' }},
  { data: { id: 'proc-domain',            source: 'process',        target: 'domain',           crossPivot: true, label: 'contacts' }},
  { data: { id: 'proc-dns_query',         source: 'process',        target: 'dns_query',        crossPivot: true, label: 'issues' }},
  { data: { id: 'proc-hash',              source: 'process',        target: 'hash',             crossPivot: true, label: 'has_image' }},
  { data: { id: 'proc-dll',               source: 'process',        target: 'dll',              crossPivot: true, label: 'loads' }},
  { data: { id: 'proc-named_pipe',        source: 'process',        target: 'named_pipe',       crossPivot: true, label: 'creates' }},
  { data: { id: 'proc-mutex',             source: 'process',        target: 'mutex',            crossPivot: true, label: 'creates' }},
  { data: { id: 'proc-service',           source: 'process',        target: 'service',          crossPivot: true, label: 'creates' }},

  // ── Command Line ─────────────────────────────────────────────────────────
  { data: { id: 'cmdline-process',        source: 'command_line',   target: 'process',          crossPivot: true, label: 'used_by' }},
  { data: { id: 'cmdline-file',           source: 'command_line',   target: 'file',             crossPivot: true, label: 'drops' }},
  { data: { id: 'cmdline-url',            source: 'command_line',   target: 'url',              crossPivot: true, label: 'contains' }},
  { data: { id: 'cmdline-ip',             source: 'command_line',   target: 'ip',               crossPivot: true, label: 'connects_to' }},

  // ── Registry ─────────────────────────────────────────────────────────────
  { data: { id: 'reg-host',               source: 'registry',       target: 'host',             crossPivot: true, label: 'exists_on' }},
  { data: { id: 'reg-file',               source: 'registry',       target: 'file',             crossPivot: true, label: 'points_to' }},
  { data: { id: 'reg-process',            source: 'registry',       target: 'process',          crossPivot: true, label: 'runs' }},

  // ── Scheduled Task ───────────────────────────────────────────────────────
  { data: { id: 'task-host',              source: 'scheduled_task', target: 'host',             crossPivot: true, label: 'runs_on' }},
  { data: { id: 'task-process',           source: 'scheduled_task', target: 'process',          crossPivot: true, label: 'executes' }},
  { data: { id: 'task-file',              source: 'scheduled_task', target: 'file',             crossPivot: true, label: 'runs' }},
  { data: { id: 'task-cmdline',           source: 'scheduled_task', target: 'command_line',     crossPivot: true, label: 'executes' }},
  { data: { id: 'task-user',              source: 'scheduled_task', target: 'user',             crossPivot: true, label: 'runs_as' }},

  // ── Startup Item ─────────────────────────────────────────────────────────
  { data: { id: 'startup-host',           source: 'startup_item',   target: 'host',             crossPivot: true, label: 'runs_on' }},
  { data: { id: 'startup-file',           source: 'startup_item',   target: 'file',             crossPivot: true, label: 'points_to' }},
  { data: { id: 'startup-process',        source: 'startup_item',   target: 'process',          crossPivot: true, label: 'executes' }},

  // ── Host ─────────────────────────────────────────────────────────────────
  { data: { id: 'host-process',           source: 'host',           target: 'process',          crossPivot: true, label: 'runs' }},
  { data: { id: 'host-file',              source: 'host',           target: 'file',             crossPivot: true, label: 'stores' }},
  { data: { id: 'host-user',              source: 'host',           target: 'user',             crossPivot: true, label: 'used_by' }},
  { data: { id: 'host-ip',                source: 'host',           target: 'ip',               crossPivot: true, label: 'assigned' }},
  { data: { id: 'host-network_session',   source: 'host',           target: 'network_session',  crossPivot: true, label: 'generates' }},
  { data: { id: 'host-vuln',              source: 'host',           target: 'vulnerability_id', crossPivot: true, label: 'has_vulnerability' }},
  { data: { id: 'host-rdp',               source: 'host',           target: 'rdp_session',      crossPivot: true, label: 'receives' }},
  { data: { id: 'host-task',              source: 'host',           target: 'scheduled_task',   crossPivot: true, label: 'has_task' }},
  { data: { id: 'host-registry',          source: 'host',           target: 'registry',         crossPivot: true, label: 'has_key' }},
  { data: { id: 'host-service',           source: 'host',           target: 'service',          crossPivot: true, label: 'runs' }},
  { data: { id: 'host-port',              source: 'host',           target: 'port',             crossPivot: true, label: 'has_open_port' }},

  // ── Share ─────────────────────────────────────────────────────────────────
  { data: { id: 'share-host',             source: 'share',          target: 'host',             crossPivot: true, label: 'hosted_on' }},
  { data: { id: 'share-user',             source: 'share',          target: 'user',             crossPivot: true, label: 'accessed_by' }},
  { data: { id: 'share-file',             source: 'share',          target: 'file',             crossPivot: true, label: 'contains' }},

  // ── Event ID ─────────────────────────────────────────────────────────────
  { data: { id: 'evtid-process',          source: 'event_id',       target: 'process',          crossPivot: true, label: 'relates_to' }},
  { data: { id: 'evtid-host',             source: 'event_id',       target: 'host',             crossPivot: true, label: 'occurs_on' }},
  { data: { id: 'evtid-user',             source: 'event_id',       target: 'user',             crossPivot: true, label: 'involves' }},

  // ── Vulnerability ID ─────────────────────────────────────────────────────
  { data: { id: 'vuln-host',              source: 'vulnerability_id', target: 'host',           crossPivot: true, label: 'affects' }},
  { data: { id: 'vuln-process',           source: 'vulnerability_id', target: 'process',        crossPivot: true, label: 'exploited_by' }},
  { data: { id: 'vuln-service',           source: 'vulnerability_id', target: 'service',        crossPivot: true, label: 'targets' }},

  // ── Service ──────────────────────────────────────────────────────────────
  { data: { id: 'service-process',        source: 'service',        target: 'process',          crossPivot: true, label: 'runs' }},
  { data: { id: 'service-host',           source: 'service',        target: 'host',             crossPivot: true, label: 'registered_on' }},
  { data: { id: 'service-file',           source: 'service',        target: 'file',             crossPivot: true, label: 'executes' }},

  // ── Mutex ────────────────────────────────────────────────────────────────
  { data: { id: 'mutex-process',          source: 'mutex',          target: 'process',          crossPivot: true, label: 'created_by' }},
  { data: { id: 'mutex-host',             source: 'mutex',          target: 'host',             crossPivot: true, label: 'observed_on' }},
  { data: { id: 'mutex-hash',             source: 'mutex',          target: 'hash',             crossPivot: true, label: 'associated_with' }},

  // ── Named Pipe ───────────────────────────────────────────────────────────
  { data: { id: 'pipe-process',           source: 'named_pipe',     target: 'process',          crossPivot: true, label: 'created_by' }},
  { data: { id: 'pipe-host',              source: 'named_pipe',     target: 'host',             crossPivot: true, label: 'observed_on' }},

  // ── DLL ──────────────────────────────────────────────────────────────────
  { data: { id: 'dll-process',            source: 'dll',            target: 'process',          crossPivot: true, label: 'loaded_by' }},
  { data: { id: 'dll-host',               source: 'dll',            target: 'host',             crossPivot: true, label: 'exists_on' }},
  { data: { id: 'dll-hash',               source: 'dll',            target: 'hash',             crossPivot: true, label: 'has_hash' }},
  { data: { id: 'dll-file',               source: 'dll',            target: 'file',             crossPivot: true, label: 'is_file' }},

  // ── User ─────────────────────────────────────────────────────────────────
  { data: { id: 'user-host',              source: 'user',           target: 'host',             crossPivot: true, label: 'logs_into' }},
  { data: { id: 'user-process',           source: 'user',           target: 'process',          crossPivot: true, label: 'executes' }},
  { data: { id: 'user-ip',                source: 'user',           target: 'ip',               crossPivot: true, label: 'originates_from' }},
  { data: { id: 'user-cloud_resource',    source: 'user',           target: 'cloud_resource',   crossPivot: true, label: 'accesses' }},
  { data: { id: 'user-email',             source: 'user',           target: 'email',            crossPivot: true, label: 'sends / receives' }},
  { data: { id: 'user-identity',          source: 'user',           target: 'identity',         crossPivot: true, label: 'mapped_to' }},
  { data: { id: 'user-share',             source: 'user',           target: 'share',            crossPivot: true, label: 'accesses' }},

  // ── Identity ─────────────────────────────────────────────────────────────
  { data: { id: 'identity-user',          source: 'identity',       target: 'user',             crossPivot: true, label: 'represents' }},
  { data: { id: 'identity-cloud',         source: 'identity',       target: 'cloud_resource',   crossPivot: true, label: 'accesses' }},
  { data: { id: 'identity-ip',            source: 'identity',       target: 'ip',               crossPivot: true, label: 'originates_from' }},

  // ── RDP Session ──────────────────────────────────────────────────────────
  { data: { id: 'rdp-host',               source: 'rdp_session',    target: 'host',             crossPivot: true, label: 'connects_to' }},
  { data: { id: 'rdp-user',               source: 'rdp_session',    target: 'user',             crossPivot: true, label: 'initiated_by' }},
  { data: { id: 'rdp-ip',                 source: 'rdp_session',    target: 'ip',               crossPivot: true, label: 'from_ip' }},
  { data: { id: 'rdp-netsess',            source: 'rdp_session',    target: 'network_session',  crossPivot: true, label: 'part_of' }},

  // ── Email ────────────────────────────────────────────────────────────────
  { data: { id: 'email-attachment',       source: 'email',          target: 'attachment',       crossPivot: true, label: 'contains' }},
  { data: { id: 'email-url',              source: 'email',          target: 'url',              crossPivot: true, label: 'contains' }},
  { data: { id: 'email-domain',           source: 'email',          target: 'domain',           crossPivot: true, label: 'originates_from' }},
  { data: { id: 'email-ip',               source: 'email',          target: 'ip',               crossPivot: true, label: 'originates_from' }},
  { data: { id: 'email-user',             source: 'email',          target: 'user',             crossPivot: true, label: 'sent_to' }},

  // ── Attachment ───────────────────────────────────────────────────────────
  { data: { id: 'attach-hash',            source: 'attachment',     target: 'hash',             crossPivot: true, label: 'has_hash' }},
  { data: { id: 'attach-file',            source: 'attachment',     target: 'file',             crossPivot: true, label: 'delivers' }},
  { data: { id: 'attach-url',             source: 'attachment',     target: 'url',              crossPivot: true, label: 'contains' }},
  { data: { id: 'attach-process',         source: 'attachment',     target: 'process',          crossPivot: true, label: 'spawns' }},

  // ── Cloud Resource ───────────────────────────────────────────────────────
  { data: { id: 'cloud-identity',         source: 'cloud_resource', target: 'identity',         crossPivot: true, label: 'owned_by' }},
  { data: { id: 'cloud-ip',               source: 'cloud_resource', target: 'ip',               crossPivot: true, label: 'exposed_via' }},
  { data: { id: 'cloud-user',             source: 'cloud_resource', target: 'user',             crossPivot: true, label: 'accessed_by' }}
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
    asn:              'T1583.003 · T1584.003 · T1590.005',
    port:             'T1046 · T1571 · T1205',
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
    service:          'T1543.003 · T1569.002 · T1035',
    mutex:            'T1480 · T1106',
    named_pipe:       'T1021.002 · T1559.001 · T1090',
    dll:              'T1574.001 · T1574.002 · T1055.001',
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
