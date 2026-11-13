#!/usr/bin/env node
/**
 * Audit one shard of sites.json.
 *
 * For every host: TLS check, HTTP probe (redirect chain, security headers),
 * headless Chrome + axe-core WCAG 2.2 A/AA, mobile overflow check.
 *
 * Usage:
 *   node scripts/audit.mjs --shard 3/20
 *   node scripts/audit.mjs --hosts bnm.md,anre.md
 *   node scripts/audit.mjs --limit 5
 */
import { promises as fs } from 'node:fs';
import path from 'node:path';
import tls from 'node:tls';
import { chromium } from 'playwright';
import AxeBuilder from '@axe-core/playwright';

const ROOT = process.cwd();
const UA =
  'gov-md-a11y/1.0 (+https://github.com/matrixneoaiagent/gov-md-a11y; public accessibility research)';
const STUB_RE =
  /(web server'?s default page|domain default page|apache2 .* default page|welcome to nginx|it works!|this domain (is|may be) for sale|domain (is )?parked|site not found|default web site page|plesk)/i;
const IMPACT_WEIGHT = { critical: 12, serious: 6, moderate: 3, minor: 1 };

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const OUT_DIR = path.resolve(ROOT, arg('out', 'results'));
const TIMEOUT = Number(arg('timeout', 45000));
const LIMIT = Number(arg('limit', 0));
const SHARD = arg('shard', '');

function parseShard(value) {
  if (!value) return null;
  const [index, total] = value.split('/').map(Number);
  if (!Number.isInteger(index) || !Number.isInteger(total) || total < 1 || index < 0 || index >= total) {
    throw new Error(`bad --shard ${value}, expected i/n`);
  }
  return { index, total };
}

function clamp(n, min = 0, max = 100) {
  return Math.max(min, Math.min(max, Math.round(n)));
}

function tlsCheck(host) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (payload) => {
      if (!done) {
        done = true;
        resolve(payload);
      }
    };
    const socket = tls.connect(
      { host, port: 443, servername: host, timeout: 10000, rejectUnauthorized: true },
      () => {
        const cert = socket.getPeerCertificate() || {};
        finish({ ok: socket.authorized === true, error: null, validTo: cert.valid_to || null });
        socket.end();
      },
    );
    socket.on('error', (err) => finish({ ok: false, error: err.code || err.message }));
    socket.on('timeout', () => {
      socket.destroy();
      finish({ ok: false, error: 'timeout' });
    });
  });
}

/** Manual redirect walk; returns final status, URL, redirect count and headers. */
async function probe(host) {
  const result = {
    startUrl: null,
    finalUrl: null,
    status: null,
    redirects: 0,
    headers: {},
    error: null,
  };
  const tryScheme = async (scheme) => {
    let url = `${scheme}://${host}/`;
    result.startUrl = url;
    for (let hop = 0; hop < 6; hop++) {
      let res;
      try {
        res = await fetch(url, {
          redirect: 'manual',
          headers: { 'user-agent': UA, accept: 'text/html,application/xhtml+xml,*/*;q=0.8' },
          signal: AbortSignal.timeout(20000),
        });
      } catch (err) {
        result.error = err.cause?.code || err.name || err.message;
        return false;
      }
      result.finalUrl = url;
      result.status = res.status;
      if (res.status >= 300 && res.status < 400) {
        const location = res.headers.get('location');
        if (!location) break;
        try {
          url = new URL(location, url).toString();
        } catch {
          break;
        }
        result.redirects++;
        continue;
      }
      for (const header of [
        'content-type',
        'strict-transport-security',
        'content-security-policy',
        'x-content-type-options',
        'x-frame-options',
        'referrer-policy',
        'permissions-policy',
      ]) {
        result.headers[header] = res.headers.get(header);
      }
      return true;
    }
    return true;
  };

  if (await tryScheme('https')) return result;
  if (await tryScheme('http')) return result;
  return result;
}

function scoreA11y(violations) {
  // Saturating penalty: a single noisy rule (e.g. contrast on 60 nodes) cannot
  // zero out the whole page, while the difference between 2 and 200 broken
  // elements still shows.
  let penalty = 0;
  for (const v of violations) {
    const weight = IMPACT_WEIGHT[v.impact] ?? IMPACT_WEIGHT.moderate;
    const scaled = weight * (1 + Math.log2(Math.max(1, v.nodes)));
    penalty += Math.min(scaled, 50);
  }
  return clamp(100 * Math.exp(-penalty / 100));
}

function scoreSecurity(probeResult, tlsResult) {
  let score = 100;
  const h = probeResult.headers || {};
  if (!String(probeResult.finalUrl || '').startsWith('https://')) score -= 40;
  if (!tlsResult.ok) score -= 30;
  if (!h['strict-transport-security']) score -= 10;
  if (!h['content-security-policy']) score -= 10;
  if (!h['x-content-type-options']) score -= 5;
  if (!h['x-frame-options'] && !h['content-security-policy']) score -= 5;
  if (!h['referrer-policy']) score -= 5;
  if (!h['permissions-policy']) score -= 5;
  return clamp(score);
}

function scorePerformance(meta) {
  const nodes = meta.nodes || 0;
  const mb = (meta.transferBytes || 0) / 1024 / 1024;
  const requests = meta.requests || 0;
  let score = 100;
  score -= Math.max(0, (nodes - 1500) / 60);
  score -= Math.max(0, (mb - 2) * 6);
  score -= Math.max(0, (requests - 80) / 6);
  return clamp(score);
}

function overallScore(parts) {
  return clamp(
    parts.a11y * 0.5 + parts.security * 0.25 + parts.performance * 0.1 + parts.mobile * 0.15,
  );
}

async function auditSite(browser, host) {
  const started = Date.now();
  const result = {
    host,
    auditedAt: new Date().toISOString(),
    url: null,
    finalHost: null,
    status: null,
    ok: false,
    stub: false,
    error: null,
    tls: null,
    headers: {},
    redirects: 0,
    axe: null,
    meta: null,
    flags: [],
    scores: null,
    durationMs: 0,
  };

  const [tlsResult, probeResult] = await Promise.all([tlsCheck(host), probe(host)]);
  result.tls = tlsResult;
  result.headers = probeResult.headers;
  result.redirects = probeResult.redirects;
  result.status = probeResult.status;
  result.url = probeResult.finalUrl || `https://${host}/`;
  try {
    result.finalHost = new URL(result.url).hostname;
  } catch {
    result.finalHost = host;
  }
  if (probeResult.error && !probeResult.status) {
    result.error = `probe: ${probeResult.error}`;
  }

  const contentType = String(probeResult.headers['content-type'] || '');
  if (contentType && !/text\/html|application\/xhtml/i.test(contentType)) {
    result.error = result.error || `not html (${contentType})`;
    result.durationMs = Date.now() - started;
    return result;
  }
  if (probeResult.status && probeResult.status >= 400 && probeResult.status !== 403) {
    result.error = result.error || `http ${probeResult.status}`;
    result.durationMs = Date.now() - started;
    return result;
  }

  const context = await browser.newContext({
    viewport: { width: 1366, height: 768 },
    userAgent: UA,
    ignoreHTTPSErrors: true,
    locale: 'ro-MD',
    timezoneId: 'Europe/Chisinau',
  });
  const page = await context.newPage();
  const consoleErrors = [];
  const failedRequests = [];
  const abortedByUs = new WeakSet();
  page.on('console', (msg) => {
    if (msg.type() === 'error') consoleErrors.push(msg.text().slice(0, 200));
  });
  page.on('requestfailed', (req) => {
    if (abortedByUs.has(req)) return;
    const reason = req.failure()?.errorText || 'failed';
    if (!/ERR_ABORTED/.test(reason)) failedRequests.push(`${req.url().slice(0, 120)} (${reason})`);
  });
  await page.route('**/*', (route) => {
    const type = route.request().resourceType();
    if (type === 'media' || type === 'font') {
      abortedByUs.add(route.request());
      return route.abort();
    }
    return route.continue();
  });

  try {
    const response = await page.goto(result.url, {
      waitUntil: 'domcontentloaded',
      timeout: TIMEOUT,
    });
    if (response) result.status = response.status();
    await page.waitForTimeout(1500);
    result.url = page.url();

    if (result.status >= 400) {
      // A 4xx/5xx root is either a WAF block or a broken site: no meaningful audit.
      result.error = `http ${result.status}`;
      result.durationMs = Date.now() - started;
      return result;
    }

    const axeRaw = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22a', 'wcag22aa'])
      .analyze();

    const impacts = Object.fromEntries(Object.keys(IMPACT_WEIGHT).map((k) => [k, 0]));
    const violations = axeRaw.violations.map((v) => {
      const impact = v.impact || 'moderate';
      impacts[impact] += 1;
      return {
        id: v.id,
        impact,
        help: v.help,
        description: v.description,
        helpUrl: v.helpUrl,
        nodes: v.nodes.length,
        sample: v.nodes.slice(0, 3).map((n) => String(n.target?.[0] || '').slice(0, 120)),
      };
    });
    violations.sort(
      (a, b) => (IMPACT_WEIGHT[b.impact] ?? 0) - (IMPACT_WEIGHT[a.impact] ?? 0) || b.nodes - a.nodes,
    );

    result.axe = {
      version: axeRaw.testEngine?.version || null,
      passes: axeRaw.passes.length,
      incomplete: axeRaw.incomplete.length,
      violations,
      impactCounts: impacts,
    };

    const meta = await page.evaluate(() => {
      const resourceEntries = performance.getEntriesByType('resource');
      const transferBytes = resourceEntries.reduce((sum, e) => sum + (e.transferSize || 0), 0);
      const nav = performance.getEntriesByType('navigation')[0];
      const badLinkText =
        /^(click here|here|read more|more|aici|aici\s*$|подробнее|далее|ссылка|link)$/i;
      const links = [...document.querySelectorAll('a')];
      return {
        lang: (document.documentElement.getAttribute('lang') || '').trim(),
        title: (document.title || '').trim(),
        hasViewport: !!document.querySelector('meta[name="viewport"]'),
        hasDescription: !!document.querySelector('meta[name="description"]'),
        h1: document.querySelectorAll('h1').length,
        nodes: document.querySelectorAll('*').length,
        links: links.length,
        badLinkText: links.filter((a) => badLinkText.test((a.textContent || '').trim())).length,
        images: document.images.length,
        imagesNoAlt: [...document.images].filter((img) => !img.hasAttribute('alt')).length,
        forms: document.forms.length,
        requests: resourceEntries.length + 1,
        transferBytes: transferBytes + (nav?.transferSize || 0),
        domContentLoaded: Math.round(nav?.domContentLoadedEventEnd || 0),
      };
    });

    await page.setViewportSize({ width: 390, height: 844 });
    await page.waitForTimeout(600);
    const mobile = await page.evaluate(() => ({
      overflow:
        Math.max(document.documentElement.scrollWidth, document.body?.scrollWidth || 0) -
        document.documentElement.clientWidth,
      viewportWidth: document.documentElement.clientWidth,
    }));

    const flags = [];
    const stub = STUB_RE.test(meta.title || '');
    result.stub = stub;
    if (stub) flags.push('stub');
    if (!meta.lang) flags.push('no-lang');
    else if (!/^[a-z]{2}(-[a-z0-9]{2,8})?$/i.test(meta.lang)) flags.push('bad-lang');
    if (!meta.title) flags.push('no-title');
    if (!meta.hasViewport) flags.push('no-viewport');
    if (meta.h1 === 0) flags.push('no-h1');
    if (meta.h1 > 1) flags.push('many-h1');
    if (meta.badLinkText > 0) flags.push('vague-link-text');
    if (mobile.overflow > 8) flags.push('mobile-overflow');
    if (result.tls && !result.tls.ok) flags.push('tls-error');
    if (!String(result.url).startsWith('https://')) flags.push('no-https');
    if (failedRequests.length > 3) flags.push('broken-requests');

    result.meta = {
      ...meta,
      mobileOverflowPx: Math.max(0, Math.round(mobile.overflow)),
      consoleErrors: consoleErrors.slice(0, 10),
      failedRequests: failedRequests.slice(0, 10),
    };
    result.flags = flags;

    const scores = {
      a11y: scoreA11y(violations),
      security: scoreSecurity(probeResult, tlsResult),
      performance: scorePerformance(meta),
      mobile: mobile.overflow > 8 ? 55 : 100,
    };
    scores.overall = overallScore(scores);
    result.scores = scores;
    result.ok = true;
  } catch (err) {
    result.error = result.error || `${err.name || 'error'}: ${String(err.message).slice(0, 200)}`;
  } finally {
    await context.close().catch(() => {});
  }

  result.durationMs = Date.now() - started;
  return result;
}

async function launchBrowser() {
  const args = ['--no-sandbox', '--disable-dev-shm-usage'];
  const explicit = [
    process.env.PW_CHROME_PATH,
    path.join(process.env.HOME || '', '.local/share/google-chrome/opt/google/chrome/google-chrome'),
    '/opt/google/chrome/chrome',
    '/usr/bin/google-chrome',
  ].filter(Boolean);

  for (const executablePath of explicit) {
    try {
      await fs.access(executablePath);
    } catch {
      continue;
    }
    try {
      const browser = await chromium.launch({ executablePath, args });
      console.log(`browser: ${executablePath}`);
      return browser;
    } catch (err) {
      console.warn(`launch ${executablePath} failed: ${err.message.split('\n')[0]}`);
    }
  }

  try {
    const browser = await chromium.launch({ channel: process.env.PW_CHANNEL || 'chrome', args });
    console.log('browser: channel chrome');
    return browser;
  } catch (err) {
    console.warn(`channel chrome unavailable: ${err.message.split('\n')[0]}`);
    const browser = await chromium.launch({ args });
    console.log('browser: bundled chromium');
    return browser;
  }
}

async function loadHosts() {
  const hostsArg = arg('hosts', '');
  if (hostsArg) return hostsArg.split(',').map((h) => h.trim()).filter(Boolean);

  const data = JSON.parse(await fs.readFile(path.join(ROOT, 'sites.json'), 'utf8'));
  const all = (data.sites || []).map((s) => s.host);
  const shard = parseShard(SHARD);
  if (!shard) return all;
  return all.filter((_, i) => i % shard.total === shard.index);
}

async function main() {
  await fs.mkdir(OUT_DIR, { recursive: true });
  const hosts = await loadHosts();
  const selected = LIMIT > 0 ? hosts.slice(0, LIMIT) : hosts;
  console.log(`auditing ${selected.length} host(s) -> ${OUT_DIR}`);

  const browser = await launchBrowser();

  let done = 0;
  let failed = 0;
  try {
    for (const host of selected) {
      const result = await auditSite(browser, host);
      if (!result.ok) failed++;
      await fs.writeFile(path.join(OUT_DIR, `${host}.json`), JSON.stringify(result, null, 2) + '\n');
      done++;
      const score = result.scores ? `overall ${result.scores.overall}` : 'no score';
      const note = result.error ? ` error="${result.error}"` : '';
      console.log(
        `[${done}/${selected.length}] ${host} ${result.status ?? '-'} ${score}${note} (${Math.round(
          result.durationMs / 1000,
        )}s)`,
      );
    }
  } finally {
    await browser.close().catch(() => {});
  }

  console.log(`finished: ${done} audited, ${failed} failed`);
  if (process.env.GITHUB_STEP_SUMMARY) {
    await fs.appendFile(
      process.env.GITHUB_STEP_SUMMARY,
      `\n- shard \`${SHARD || 'local'}\`: ${done} sites, ${failed} failed\n`,
    );
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});