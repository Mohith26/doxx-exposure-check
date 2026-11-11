// Derives per-service exploitation evidence from CISA's Known Exploited Vulnerabilities catalog.
// usage: curl -sL https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -o /tmp/kev.json
//        node scripts/kev_ports.mjs /tmp/kev.json   ->  data/kev_ports.json
import { readFileSync, writeFileSync } from 'node:fs';

// port -> service name (IANA) and a case-insensitive pattern over vendor/product/name
export const SERVICES = [
  { port: 21, proto: 'TCP', service: 'FTP', re: /\bftp\b|vsftpd|proftpd|filezilla server/i },
  { port: 22, proto: 'TCP', service: 'SSH', re: /openssh|\bssh\b|libssh/i },
  { port: 23, proto: 'TCP', service: 'Telnet', re: /telnet/i },
  { port: 445, proto: 'TCP', service: 'SMB', re: /\bsmb|server message block|samba/i },
  { port: 1433, proto: 'TCP', service: 'MS SQL Server', re: /sql server/i },
  { port: 2375, proto: 'TCP', service: 'Docker API', re: /docker/i },
  { port: 3000, proto: 'TCP', service: 'Grafana / dev server', re: /grafana/i },
  { port: 3306, proto: 'TCP', service: 'MySQL', re: /mysql|mariadb/i },
  { port: 3389, proto: 'TCP', service: 'RDP', re: /remote desktop|\brdp\b/i },
  { port: 5432, proto: 'TCP', service: 'PostgreSQL', re: /postgres/i },
  { port: 5900, proto: 'TCP', service: 'VNC', re: /\bvnc\b/i },
  { port: 6379, proto: 'TCP', service: 'Redis', re: /redis/i },
  { port: 6443, proto: 'TCP', service: 'Kubernetes API', re: /kubernetes|kubelet/i },
  { port: 8080, proto: 'TCP', service: 'Jenkins / admin HTTP', re: /jenkins|tomcat/i },
  { port: 9200, proto: 'TCP', service: 'Elasticsearch', re: /elasticsearch|kibana/i },
  { port: 11211, proto: 'TCP', service: 'Memcached', re: /memcached/i },
  { port: 27017, proto: 'TCP', service: 'MongoDB', re: /mongodb/i },
];

export function kevCounts(kev) {
  return SERVICES.map((s) => {
    const hits = kev.vulnerabilities.filter((v) => s.re.test(`${v.vendorProject} ${v.product} ${v.vulnerabilityName}`));
    return { port: s.port, proto: s.proto, service: s.service, kev: hits.length, ransomware: hits.filter((v) => v.knownRansomwareCampaignUse === 'Known').length, examples: hits.slice(-3).map((v) => v.cveID) };
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const kev = JSON.parse(readFileSync(process.argv[2] || '/tmp/kev.json'));
  const out = { source: 'CISA Known Exploited Vulnerabilities catalog', catalogVersion: kev.catalogVersion, dateReleased: kev.dateReleased, totalEntries: kev.count, services: kevCounts(kev) };
  writeFileSync(new URL('../data/kev_ports.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
  console.log(out.services.map((s) => `${s.port} ${s.service}: ${s.kev}`).join('\n'));
}
