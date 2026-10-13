import net from "node:net";

/**
 * IP-Klassifikation für den Egress-Schutz.
 *
 * Ansatz: Allowlist statt Blocklist-Lücken. IPv4 ist nur erlaubt, wenn die Adresse
 * nicht in einem der speziellen Bereiche (IANA Special-Purpose Registry) liegt.
 * IPv6 ist nur innerhalb von 2000::/3 (Global Unicast) erlaubt und auch dort
 * werden Spezialbereiche (Dokumentation, Teredo, 6to4, ORCHID usw.) blockiert.
 * IPv4-mapped/-kompatible und NAT64-Adressen werden auf ihre eingebettete
 * IPv4-Adresse zurückgeführt und erneut geprüft.
 */

type Cidr = { base: bigint; bits: number; size: 32 | 128; label: string };

function ipv4ToBigInt(ip: string): bigint {
  const parts = ip.split(".").map((p) => Number(p));
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) {
    throw new Error(`Ungültige IPv4-Adresse: ${ip}`);
  }
  return parts.reduce((acc, p) => (acc << 8n) + BigInt(p), 0n);
}

export function ipv6ToBigInt(ip: string): bigint {
  let addr = ip;
  // Eingebettete IPv4-Notation am Ende (z. B. ::ffff:127.0.0.1)
  const v4Match = addr.match(/(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (v4Match && v4Match[1]) {
    const v4 = ipv4ToBigInt(v4Match[1]);
    const hi = ((v4 >> 16n) & 0xffffn).toString(16);
    const lo = (v4 & 0xffffn).toString(16);
    addr = addr.slice(0, addr.length - v4Match[1].length) + `${hi}:${lo}`;
  }
  const halves = addr.split("::");
  if (halves.length > 2) throw new Error(`Ungültige IPv6-Adresse: ${ip}`);
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 && head.length !== 8) throw new Error(`Ungültige IPv6-Adresse: ${ip}`);
  if (missing < 0) throw new Error(`Ungültige IPv6-Adresse: ${ip}`);
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill("0"), ...tail];
  return groups.reduce((acc, g) => {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) throw new Error(`Ungültige IPv6-Adresse: ${ip}`);
    return (acc << 16n) + BigInt(parseInt(g, 16));
  }, 0n);
}

function cidr(spec: string, label: string): Cidr {
  const [addr, bitsStr] = spec.split("/");
  if (!addr || !bitsStr) throw new Error(`Ungültiges CIDR: ${spec}`);
  const bits = Number(bitsStr);
  if (net.isIPv4(addr)) return { base: ipv4ToBigInt(addr), bits, size: 32, label };
  return { base: ipv6ToBigInt(addr), bits, size: 128, label };
}

function inCidr(value: bigint, size: 32 | 128, range: Cidr): boolean {
  if (range.size !== size) return false;
  const shift = BigInt(size - range.bits);
  return value >> shift === range.base >> shift;
}

const BLOCKED_V4: Cidr[] = [
  cidr("0.0.0.0/8", "«Dieses Netz» (0.0.0.0/8)"),
  cidr("10.0.0.0/8", "Privates Netz (RFC 1918)"),
  cidr("100.64.0.0/10", "Carrier-Grade NAT (RFC 6598)"),
  cidr("127.0.0.0/8", "Loopback"),
  cidr("169.254.0.0/16", "Link-Local / Cloud-Metadaten"),
  cidr("172.16.0.0/12", "Privates Netz (RFC 1918)"),
  cidr("192.0.0.0/24", "IETF-Protokollzuweisungen"),
  cidr("192.0.2.0/24", "Dokumentation (TEST-NET-1)"),
  cidr("192.31.196.0/24", "AS112"),
  cidr("192.52.193.0/24", "AMT"),
  cidr("192.88.99.0/24", "6to4-Relay (veraltet)"),
  cidr("192.168.0.0/16", "Privates Netz (RFC 1918)"),
  cidr("192.175.48.0/24", "AS112 Direct Delegation"),
  cidr("198.18.0.0/15", "Benchmarking"),
  cidr("198.51.100.0/24", "Dokumentation (TEST-NET-2)"),
  cidr("203.0.113.0/24", "Dokumentation (TEST-NET-3)"),
  cidr("224.0.0.0/4", "Multicast"),
  cidr("240.0.0.0/4", "Reserviert / Broadcast"),
];

const GLOBAL_UNICAST_V6 = cidr("2000::/3", "Global Unicast");
const BLOCKED_V6: Cidr[] = [
  cidr("2001::/23", "IETF-Protokollzuweisungen (inkl. Teredo)"),
  cidr("2001:db8::/32", "Dokumentation"),
  cidr("2002::/16", "6to4"),
  cidr("3fff::/20", "Dokumentation"),
  cidr("2620:4f:8000::/48", "AS112"),
];
const NAT64 = [cidr("64:ff9b::/96", "NAT64"), cidr("64:ff9b:1::/48", "Lokales NAT64")];
const V4_MAPPED = cidr("::ffff:0:0/96", "IPv4-mapped");
const V4_COMPAT = cidr("::/96", "IPv4-kompatibel (veraltet)");
const CLOUD_METADATA_V6 = cidr("fd00:ec2::254/128", "AWS-Metadaten (IPv6)");

export type IpVerdict = { allowed: true; ip: string; family: 4 | 6 } | { allowed: false; ip: string; reason: string };

export function classifyIp(ip: string, extraAllow: Cidr[] = []): IpVerdict {
  const family = net.isIP(ip);
  if (family === 4) {
    const v = ipv4ToBigInt(ip);
    if (extraAllow.some((r) => inCidr(v, 32, r))) return { allowed: true, ip, family: 4 };
    const hit = BLOCKED_V4.find((r) => inCidr(v, 32, r));
    if (hit) return { allowed: false, ip, reason: `Nicht öffentliche Adresse: ${hit.label}` };
    return { allowed: true, ip, family: 4 };
  }
  if (family === 6) {
    const v = ipv6ToBigInt(ip);
    if (extraAllow.some((r) => inCidr(v, 128, r))) return { allowed: true, ip, family: 6 };
    if (inCidr(v, 128, CLOUD_METADATA_V6)) return { allowed: false, ip, reason: "Cloud-Metadaten-Adresse" };
    // Eingebettete IPv4 erneut prüfen (mapped, kompatibel, NAT64)
    for (const r of [V4_MAPPED, V4_COMPAT, ...NAT64]) {
      if (inCidr(v, 128, r)) {
        const embedded = v & 0xffffffffn;
        const v4 = [24n, 16n, 8n, 0n].map((s) => Number((embedded >> s) & 0xffn)).join(".");
        const inner = classifyIp(v4, extraAllow);
        if (!inner.allowed) return { allowed: false, ip, reason: `${r.label} mit ${inner.reason}` };
        // Selbst bei öffentlicher eingebetteter Adresse: Übersetzungsbereiche nicht direkt ansprechen.
        return { allowed: false, ip, reason: `${r.label}-Adressen werden nicht direkt angesprochen` };
      }
    }
    if (!inCidr(v, 128, GLOBAL_UNICAST_V6)) {
      return { allowed: false, ip, reason: "Keine globale Unicast-IPv6-Adresse (Loopback, Link-Local, ULA, Multicast o. Ä.)" };
    }
    const hit = BLOCKED_V6.find((r) => inCidr(v, 128, r));
    if (hit) return { allowed: false, ip, reason: `Spezialbereich: ${hit.label}` };
    return { allowed: true, ip, family: 6 };
  }
  return { allowed: false, ip, reason: "Keine gültige IP-Adresse" };
}

export function parseCidrList(spec: string | undefined): Cidr[] {
  if (!spec) return [];
  return spec
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => cidr(s.includes("/") ? s : `${s}/${net.isIPv4(s) ? 32 : 128}`, "Test-Ausnahme"));
}

export type { Cidr };
