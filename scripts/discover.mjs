#!/usr/bin/env node
/**
 * Discovery: Certificate Transparency -> list of Moldovan public sector hosts.
 *
 * Sources:
 *   1. crt.sh search for %.gov.md (all subdomains ever seen in a certificate)
 *   2. sites.extra.txt (manual additions outside .gov.md)
 *
 * Every candidate is normalized and DNS-resolved; dead hosts are dropped but
 * remembered, so a temporarily down site comes back without a rediscovery.
 *
 * Output: sites.json
 */
import { promises as fs } from 'node:fs';
import dns from 'node:dns/promises';
import path from 'node:path';

const ROOT = process.cwd();
const OUT = path.join(ROOT, 'sites.json');
const EXTRA = path.join(ROOT, 'sites.extra.txt');
const UA = 'gov-md-a11y/1.0 (+https://github.com/matrixneoaiagent/gov-md-a11y)';
const CRT_URL = 'https://crt.sh/?q=%25.gov.md&output=json';
const HOST_RE = /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;

const log = (...a) => console.log(new Date().toISOString(), ...a);

function normalize(raw) {
  let h = String(raw || '')
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^[a-z0-9+.-]+:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '')
    .replace(/^\*\./, '')
    .replace(/\.$/, '');
  if (!h || h.includes('@') || h.includes('_') || h.includes(' ') || h.includes('/')) return null;
  if (!h.endsWith('.gov.md')) return null;
  if (!HOST_RE.test(h)) return null;
  if (h.split('.').some((label) => label.length > 63)) return null;
  return h;
}

async function fetchJson(url, { attempts = 4, timeout = 120000 } = {}) {
  let lastErr;
  for (let i = 1; i <= attempts; i++) {
    try {
      const res = await fetch(url, {
        headers: { 'user-agent': UA, accept: 'application/json' },
        signal: AbortSignal.timeout(timeout),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (!Array.isArray(data)) throw new Error('unexpected payload');
      return data;
    } catch (err) {
      lastErr = err;
      log(`crt.sh attempt ${i}/${attempts} failed: ${err.message}`);
      if (i < attempts) await new Promise((r) => setTimeout(r, 5000 * i));
    }
  }
  throw lastErr;
}

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('dns timeout')), ms)),
  ]);
}

async function resolves(host) {
  const opts = { ttl: true };
  for (let attempt = 1; attempt <= 2; attempt++) {
    const results = await Promise.allSettled([
      withTimeout(dns.resolve4(host, opts), 8000),
      withTimeout(dns.resolve6(host, opts), 8000),
    ]);
    const ok = results.some((r) => r.status === 'fulfilled' && Array.isArray(r.value) && r.value.length > 0);
    if (ok) return true;
    if (attempt === 1) await new Promise((r) => setTimeout(r, 400));
  }
  // Runner DNS is throttled/unreliable for hundreds of lookups at once; ask DoH.
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`,
      {
        headers: { accept: 'application/dns-json', 'user-agent': UA },
        signal: AbortSignal.timeout(8000),
      },
    );
    if (!res.ok) return false;
    const data = await res.json();
    return (data.Answer || []).some((a) => a.type === 1 || a.type === 28);
  } catch {
    return false;
  }
}

async function mapPool(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return results;
}

async function readPrevious() {
  try {
    const data = JSON.parse(await fs.readFile(OUT, 'utf8'));
    return new Map((data.sites || []).map((s) => [s.host, s]));
  } catch {
    return new Map();
  }
}

async function readKnownDead() {
  try {
    const data = JSON.parse(await fs.readFile(OUT, 'utf8'));
    return Array.isArray(data.dead) ? data.dead : [];
  } catch {
    return [];
  }
}

async function readExtra() {
  try {
    const text = await fs.readFile(EXTRA, 'utf8');
    return text
      .split('\n')
      .map((line) => line.replace(/#.*$/, '').trim())
      .filter(Boolean)
      .map((h) => h.toLowerCase())
      .filter((h) => HOST_RE.test(h));
  } catch {
    return [];
  }
}

async function main() {
  const previous = await readPrevious();
  const knownDead = await readKnownDead();
  const extra = await readExtra();
  const candidates = new Set([...extra, ...previous.keys(), ...knownDead]);

  try {
    const rows = await fetchJson(CRT_URL);
    let fromCrt = 0;
    for (const row of rows) {
      for (const name of String(row.name_value || '').split('\n')) {
        const host = normalize(name);
        if (host) {
          candidates.add(host);
          fromCrt++;
        }
      }
    }
    log(`crt.sh rows: ${rows.length}, candidate mentions: ${fromCrt}`);
  } catch (err) {
    log(`crt.sh unavailable (${err.message}); keeping previous list`);
    for (const host of previous.keys()) candidates.add(host);
  }

  const hosts = [...candidates].sort();
  log(`candidates: ${hosts.length}`);

  const checks = await mapPool(hosts, 12, async (host) => ({ host, alive: await resolves(host) }));
  log(`dns/DoH ok: ${checks.filter((c) => c.alive).length}, unreachable: ${checks.filter((c) => !c.alive).length}`);
  const alive = checks.filter((c) => c.alive).map((c) => c.host);
  const dead = checks.filter((c) => !c.alive).map((c) => c.host);

  const now = new Date().toISOString().slice(0, 10);
  const sites = checks
    .filter((c) => c.alive)
    .map((c) => {
      const prev = previous.get(c.host);
      return {
        host: c.host,
        firstSeen: prev?.firstSeen || now,
        lastSeen: now,
        source: extra.includes(c.host) ? 'manual' : 'crt.sh',
      };
    })
    .sort((a, b) => a.host.localeCompare(b.host));

  const payload = {
    generatedAt: new Date().toISOString(),
    source: 'crt.sh %.gov.md + sites.extra.txt',
    total: sites.length,
    dead: dead.sort(),
    sites,
  };
  await fs.writeFile(OUT, JSON.stringify(payload, null, 2) + '\n');

  const newHosts = sites.filter((s) => s.firstSeen === now).map((s) => s.host);
  log(`wrote ${OUT}: ${sites.length} live hosts, ${newHosts.length} first seen today`);

  const summary = process.env.GITHUB_STEP_SUMMARY;
  if (summary) {
    const lines = [
      '## gov-md-a11y discovery',
      '',
      `- live hosts: **${sites.length}**`,
      `- dns failures kept out: ${dead.length}`,
      `- first seen today: ${newHosts.length}`,
      '',
      newHosts.length ? newHosts.slice(0, 40).map((h) => `- \`${h}\``).join('\n') : '_no new hosts_',
      '',
    ];
    await fs.appendFile(summary, lines.join('\n'));
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});