#!/usr/bin/env node
/**
 * Merge per-site audit results into a public dataset and a static report.
 *
 * Input:  results/*.json
 * Output: docs/index.html, docs/report.md, docs/data/sites.json,
 *         docs/data/summary.json, docs/data/site/<host>.json
 */
import { promises as fs } from 'node:fs';
import path from 'node:path';

const ROOT = process.cwd();
const RESULTS = path.resolve(ROOT, 'results');
const DOCS = path.resolve(ROOT, 'docs');
const DATA = path.join(DOCS, 'data');

const IMPACT_RU = { critical: 'критично', serious: 'серьёзно', moderate: 'умеренно', minor: 'мелко' };
const WEIGHT = { critical: 12, serious: 6, moderate: 3, minor: 1 };

function clamp(n) {
  return Math.max(0, Math.min(100, Math.round(n)));
}

function pct(part, total) {
  return total ? Math.round((part / total) * 100) : 0;
}

async function readResults() {
  let files = [];
  try {
    files = (await fs.readdir(RESULTS)).filter((f) => f.endsWith('.json'));
  } catch {
    return [];
  }
  const rows = [];
  for (const file of files) {
    try {
      rows.push(JSON.parse(await fs.readFile(path.join(RESULTS, file), 'utf8')));
    } catch (err) {
      console.warn(`skip ${file}: ${err.message}`);
    }
  }
  return rows;
}

function dedupe(rows) {
  // A redirect to another audited host would otherwise appear twice.
  const byHost = new Map();
  for (const row of rows) {
    const key = row.finalHost || row.host;
    const prev = byHost.get(key);
    if (!prev) {
      byHost.set(key, row);
      continue;
    }
    const better =
      (row.ok && !prev.ok) ||
      (row.ok === prev.ok && (row.scores?.overall ?? -1) > (prev.scores?.overall ?? -1));
    if (better) byHost.set(key, row);
  }
  return [...byHost.values()];
}

function summarize(rows) {
  const stubs = rows.filter((r) => r.stub);
  const audited = rows.filter((r) => r.ok && !r.stub);
  const avg = (key) =>
    audited.length
      ? Math.round(audited.reduce((sum, r) => sum + (r.scores?.[key] ?? 0), 0) / audited.length)
      : 0;

  const violationMap = new Map();
  for (const row of audited) {
    for (const v of row.axe?.violations || []) {
      const entry = violationMap.get(v.id) || {
        id: v.id,
        help: v.help,
        impact: v.impact,
        helpUrl: v.helpUrl,
        sites: 0,
        nodes: 0,
        pages: [],
      };
      entry.sites += 1;
      entry.nodes += v.nodes;
      if (entry.pages.length < 5) entry.pages.push(row.host);
      violationMap.set(v.id, entry);
    }
  }
  const violations = [...violationMap.values()].sort(
    (a, b) => b.sites - a.sites || b.nodes - a.nodes,
  );

  const impacts = { critical: 0, serious: 0, moderate: 0, minor: 0 };
  for (const row of audited) {
    for (const [k, n] of Object.entries(row.axe?.impactCounts || {})) impacts[k] += n;
  }

  const flags = new Map();
  for (const row of audited) {
    for (const f of row.flags || []) flags.set(f, (flags.get(f) || 0) + 1);
  }

  return {
    generatedAt: new Date().toISOString(),
    total: rows.length,
    audited: audited.length,
    stubs: stubs.length,
    stubList: stubs.map((r) => r.host).sort(),
    failed: rows.length - audited.length - stubs.length,
    average: {
      overall: avg('overall'),
      a11y: avg('a11y'),
      security: avg('security'),
      performance: avg('performance'),
      mobile: avg('mobile'),
    },
    cleanPages: audited.filter((r) => (r.axe?.violations?.length || 0) === 0).length,
    perfectScores: audited.filter((r) => (r.scores?.overall || 0) >= 90).length,
    https: audited.filter((r) => String(r.url).startsWith('https://')).length,
    tlsOk: audited.filter((r) => r.tls?.ok).length,
    hsts: audited.filter((r) => r.headers?.['strict-transport-security']).length,
    csp: audited.filter((r) => r.headers?.['content-security-policy']).length,
    lang: audited.filter((r) => (r.meta?.lang || '').length >= 2).length,
    viewport: audited.filter((r) => r.meta?.hasViewport).length,
    mobileOverflow: audited.filter((r) => (r.meta?.mobileOverflowPx || 0) > 8).length,
    impacts,
    violations,
    flags: [...flags.entries()]
      .map(([id, sites]) => ({ id, sites }))
      .sort((a, b) => b.sites - a.sites),
    worst: [...audited].sort((a, b) => a.scores.overall - b.scores.overall).slice(0, 25),
    best: [...audited].sort((a, b) => b.scores.overall - a.scores.overall).slice(0, 10),
  };
}

function compact(row) {
  return {
    host: row.host,
    finalHost: row.finalHost,
    url: row.url,
    ok: row.ok,
    stub: row.stub || false,
    error: row.error,
    status: row.status,
    scores: row.scores,
    flags: row.flags,
    violations: (row.axe?.violations || []).map((v) => ({
      id: v.id,
      impact: v.impact,
      help: v.help,
      helpUrl: v.helpUrl,
      nodes: v.nodes,
    })),
    impactCounts: row.axe?.impactCounts || null,
    tls: row.tls ? { ok: row.tls.ok, error: row.tls.error, validTo: row.tls.validTo } : null,
    meta: row.meta
      ? {
          lang: row.meta.lang,
          title: row.meta.title,
          h1: row.meta.h1,
          nodes: row.meta.nodes,
          transferBytes: row.meta.transferBytes,
          requests: row.meta.requests,
          mobileOverflowPx: row.meta.mobileOverflowPx,
          hasViewport: row.meta.hasViewport,
        }
      : null,
    durationMs: row.durationMs,
    auditedAt: row.auditedAt,
  };
}

function fmtBytes(bytes) {
  if (!bytes) return '—';
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} КБ`;
  return `${(bytes / 1024 / 1024).toFixed(1)} МБ`;
}

function renderReport(summary, dateLabel) {
  const s = summary;
  const lines = [];
  lines.push(`# Доступность государственных сайтов Молдовы — ${dateLabel}`, '');
  lines.push(
    `Автоматический аудит ${s.discovered ?? s.total} хостов зоны \`.gov.md\`: ${s.total} уникальных адресов после склейки редиректов, ${s.audited} проверены. ` +
      `Средняя оценка — **${s.average.overall}** из 100, полностью без нарушений WCAG — ${s.cleanPages} страниц (${pct(
        s.cleanPages,
        s.audited,
      )}%).${s.stubs ? ` Заглушек хостера: ${s.stubs} — они не ранжируются.` : ''}`,
    '',
  );
  lines.push('## Сводка', '');
  lines.push('| Показатель | Значение |', '|---|---|');
  lines.push(`| Проверено страниц | ${s.audited} |`);
  lines.push(`| Не ответили | ${s.failed} |`);
  lines.push(`| Заглушки хостера | ${s.stubs} |`);
  lines.push(`| Средняя оценка | ${s.average.overall} |`);
  lines.push(`| Доступность (axe) | ${s.average.a11y} |`);
  lines.push(`| Безопасность заголовков | ${s.average.security} |`);
  lines.push(`| Мобильная вёрстка | ${s.average.mobile} |`);
  lines.push(`| HTTPS | ${pct(s.https, s.audited)}% |`);
  lines.push(`| Валидный TLS-сертификат | ${pct(s.tlsOk, s.audited)}% |`);
  lines.push(`| HSTS | ${pct(s.hsts, s.audited)}% |`);
  lines.push(`| CSP | ${pct(s.csp, s.audited)}% |`);
  lines.push(`| Указан \`lang\` | ${pct(s.lang, s.audited)}% |`);
  lines.push(`| Есть \`meta viewport\` | ${pct(s.viewport, s.audited)}% |`);
  lines.push(`| Горизонтальная прокрутка на 390 px | ${pct(s.mobileOverflow, s.audited)}% |`, '');

  lines.push('## Самые проблемные сайты', '');
  lines.push('| # | Сайт | Оценка | Доступность | Нарушений | Критичных |', '|---|---|---|---|---|---|');
  s.worst.slice(0, 20).forEach((row, i) => {
    lines.push(
      `| ${i + 1} | [${row.host}](${row.url}) | ${row.scores.overall} | ${row.scores.a11y} | ${
        row.axe?.violations?.length || 0
      } | ${row.axe?.impactCounts?.critical || 0} |`,
    );
  });
  lines.push('');

  lines.push('## Что встречается чаще всего', '');
  lines.push('| Нарушение | Сайтов | Элементов | Уровень |', '|---|---|---|---|');
  for (const v of s.violations.slice(0, 15)) {
    lines.push(`| [${v.id}](${v.helpUrl}) — ${v.help} | ${v.sites} | ${v.nodes} | ${IMPACT_RU[v.impact] || v.impact} |`);
  }
  lines.push('');

  const flagNames = {
    'no-lang': 'не указан язык страницы',
    'bad-lang': 'некорректный код языка',
    'no-title': 'нет `<title>`',
    'no-viewport': 'нет `meta viewport` (страница не адаптируется)',
    'no-h1': 'нет заголовка `<h1>`',
    'many-h1': 'несколько `<h1>`',
    'vague-link-text': 'ссылки вида «здесь», «подробнее»',
    'mobile-overflow': 'горизонтальная прокрутка на мобильном',
    'tls-error': 'ошибка TLS-сертификата',
    'no-https': 'сайт открывается по HTTP',
    'broken-requests': 'битые запросы ресурсов',
    stub: 'служебная страница хостера (не ранжируется)',
  };
  lines.push('## Технические флаги', '');
  lines.push('| Флаг | Сайтов | Что значит |', '|---|---|---|');
  for (const f of s.flags) {
    lines.push(`| \`${f.id}\` | ${f.sites} | ${flagNames[f.id] || f.id} |`);
  }
  lines.push('');

  if (s.stubList?.length) {
    lines.push('## Заглушки хостера', '');
    lines.push(
      'Эти домены резолвятся, но отдают служебную страницу Plesk или хостинга. Они не ранжируются: проверять там нечего, кроме просроченного сертификата.',
      '',
      s.stubList.map((h) => `- \`${h}\``).join('\n'),
      '',
    );
  }

  lines.push('## Как считалось', '');
  lines.push(
    '- Оценка **доступности**: `100 × e^(−P/100)`, где P — сумма штрафов по правилам axe: 12/6/3/1 балла за критичное, серьёзное, умеренное и мелкое нарушение, умноженные на `1 + log₂(число элементов)`; одно правило даёт не больше 50 баллов штрафа.',
    '- Оценка **безопасности**: HTTPS, валидный сертификат, HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`.',
    '- Оценка **производительности**: число DOM-узлов, вес страницы, количество запросов.',
    '- **Мобильная** оценка: отсутствие горизонтальной прокрутки при ширине 390 px.',
    '- Итог: 50 % доступность, 25 % безопасность, 15 % мобильность, 10 % производительность.',
    '',
  );
  lines.push('## Ограничения', '');
  lines.push(
    '- Проверяется только главная страница; внутренние разделы могут быть лучше или хуже.',
    '- axe-core находит примерно треть проблем WCAG; ручная проверка (клавиатура, скринридер) не заменяется.',
    '- Часть госсайтов блокирует запросы из дата-центров — такие хосты попадают в «не ответили».',
    '- Оценка — не рейтинг учреждения, а срез одной страницы на дату аудита.',
    '',
  );
  lines.push('## Данные', '');
  lines.push(
    '- `docs/data/sites.json` — все результаты, `docs/data/site/<host>.json` — детали по сайту.',
    '- Лицензия данных: CC BY 4.0. Код: MIT.',
    '',
  );
  return lines.join('\n');
}

function renderHtml(summary, dateLabel, repoUrl) {
  const payload = JSON.stringify({
    summary: {
      ...summary,
      violations: summary.violations.slice(0, 30),
      worst: summary.worst.map(compact),
      flags: summary.flags,
    },
    sites: summary.sites,
  }).replace(/</g, '\\u003c');

  return `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Доступность госсайтов Молдовы — ${dateLabel}</title>
<meta name="description" content="Автоматический аудит доступности, безопасности и мобильной вёрстки сайтов зоны .gov.md">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' fill='%230b6b4f'/><text x='16' y='23' font-family='Georgia,serif' font-size='19' text-anchor='middle' fill='%23fffdf8'>A</text></svg>">
<style>
  :root {
    --paper: #f6f4ef;
    --ink: #191813;
    --muted: #6b675c;
    --rule: #ddd8cc;
    --card: #fffdf8;
    --accent: #0b6b4f;
    --warn: #a8551a;
    --bad: #9b2c2c;
    --shadow: 0 1px 0 rgba(25, 24, 19, .04);
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --paper: #14140f;
      --ink: #ece8dc;
      --muted: #9a9484;
      --rule: #322f26;
      --card: #1b1a14;
      --accent: #59c39a;
      --warn: #e0a266;
      --bad: #e08080;
      --shadow: none;
    }
  }
  * { box-sizing: border-box; }
  html { -webkit-text-size-adjust: 100%; }
  body {
    margin: 0;
    background: var(--paper);
    color: var(--ink);
    font: 16px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    font-variant-numeric: tabular-nums;
  }
  .wrap { max-width: 1120px; margin: 0 auto; padding: 0 24px; }
  header.top { padding: 72px 0 40px; border-bottom: 1px solid var(--rule); }
  .eyebrow {
    font-size: 12px; letter-spacing: .14em; text-transform: uppercase;
    color: var(--muted); margin: 0 0 18px;
  }
  h1 {
    font-family: ui-serif, Georgia, "Times New Roman", serif;
    font-weight: 600; font-size: clamp(32px, 5vw, 54px); line-height: 1.05;
    letter-spacing: -0.015em; margin: 0 0 18px; max-width: 18ch;
  }
  .lead { color: var(--muted); max-width: 62ch; font-size: 17px; margin: 0 0 28px; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1px; background: var(--rule); border: 1px solid var(--rule); }
  .stat { background: var(--card); padding: 18px 20px; }
  .stat b { display: block; font-size: 30px; line-height: 1.1; font-weight: 650; letter-spacing: -0.02em; }
  .stat span { color: var(--muted); font-size: 12.5px; }
  section { padding: 52px 0; border-bottom: 1px solid var(--rule); }
  h2 {
    font-family: ui-serif, Georgia, serif; font-weight: 600;
    font-size: 26px; letter-spacing: -0.01em; margin: 0 0 8px;
  }
  .sub { color: var(--muted); margin: 0 0 24px; font-size: 15px; }
  .controls { display: flex; flex-wrap: wrap; gap: 8px; margin: 0 0 18px; align-items: center; }
  .chip {
    appearance: none; border: 1px solid var(--rule); background: var(--card); color: var(--ink);
    padding: 7px 13px; border-radius: 999px; font: inherit; font-size: 13.5px; cursor: pointer;
  }
  .chip[aria-pressed="true"] { border-color: var(--ink); }
  input[type="search"] {
    flex: 1 1 220px; min-width: 180px; padding: 8px 12px; border: 1px solid var(--rule);
    border-radius: 999px; background: var(--card); color: var(--ink); font: inherit; font-size: 14px;
  }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid var(--rule); vertical-align: middle; }
  th { font-size: 11.5px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); font-weight: 600; cursor: pointer; user-select: none; white-space: nowrap; }
  th.num, td.num { text-align: right; }
  tbody tr:hover { background: var(--card); }
  td.host { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 13px; }
  td.host a { color: var(--ink); text-decoration: none; border-bottom: 1px solid var(--rule); }
  td.host a:hover { border-color: var(--accent); color: var(--accent); }
  .score { display: flex; align-items: center; gap: 8px; justify-content: flex-end; }
  .bar { width: 46px; height: 4px; background: var(--rule); border-radius: 2px; overflow: hidden; }
  .bar i { display: block; height: 100%; background: var(--accent); }
  .s-bad .bar i { background: var(--bad); }
  .s-warn .bar i { background: var(--warn); }
  .dots { color: var(--muted); font-size: 12px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px; }
  .card { background: var(--card); border: 1px solid var(--rule); padding: 16px 18px; box-shadow: var(--shadow); }
  .card .k { font-family: ui-monospace, Menlo, monospace; font-size: 13px; color: var(--accent); }
  .card p { margin: 6px 0 10px; font-size: 14px; }
  .card .m { color: var(--muted); font-size: 12.5px; }
  .impact { display: inline-block; font-size: 11px; letter-spacing: .04em; text-transform: uppercase; padding: 2px 7px; border: 1px solid currentColor; border-radius: 3px; }
  .impact.critical { color: var(--bad); }
  .impact.serious { color: var(--warn); }
  .impact.moderate, .impact.minor { color: var(--muted); }
  .method { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 24px; }
  .method p, .method li { color: var(--muted); font-size: 14.5px; }
  .method h3 { font-size: 15px; margin: 0 0 8px; }
  ul { margin: 8px 0; padding-left: 20px; }
  footer { padding: 40px 0 64px; color: var(--muted); font-size: 13.5px; }
  footer a { color: inherit; }
  .note { border-left: 2px solid var(--accent); padding: 4px 0 4px 16px; color: var(--muted); font-size: 14px; margin: 20px 0 0; }
  @media (max-width: 720px) {
    header.top { padding: 48px 0 28px; }
    section { padding: 36px 0; }
    .hide-sm { display: none; }
    th, td { padding: 9px 6px; }
  }
</style>
</head>
<body>
<header class="top">
  <div class="wrap">
    <p class="eyebrow">Открытые данные · Республика Молдова</p>
    <h1>Доступность государственных сайтов</h1>
    <p class="lead">Автоматический аудит ${summary.discovered} хостов зоны <code>.gov.md</code>: ${summary.total} уникальных адресов после склейки редиректов, ${summary.audited} проверены по WCAG 2.2 A/AA, заголовкам безопасности и мобильной вёрстке${summary.stubs ? `; ещё ${summary.stubs} — заглушки хостера` : ''}. Срез на ${dateLabel}</p>
    <div class="stats">
      <div class="stat"><b>${summary.average.overall}</b><span>средняя оценка из 100</span></div>
      <div class="stat"><b>${summary.cleanPages}</b><span>страниц без нарушений WCAG</span></div>
      <div class="stat"><b>${summary.audited}</b><span>проверено из ${summary.total} адресов</span></div>
      <div class="stat"><b>${Math.round((summary.https / Math.max(summary.audited, 1)) * 100)}%</b><span>работают по HTTPS</span></div>
    </div>
    <p class="note">Оценка — не рейтинг учреждения, а срез главной страницы на дату. Методика и ограничения — ниже.</p>
  </div>
</header>

<main>
  <section>
    <div class="wrap">
      <h2>Частые нарушения</h2>
      <p class="sub">Сколько сайтов затронуто каждым правилом axe-core.</p>
      <div class="cards" id="violations"></div>
    </div>
  </section>

  <section>
    <div class="wrap">
      <h2>Все сайты</h2>
      <p class="sub">Нажмите на заголовок столбца, чтобы отсортировать.</p>
      <div class="controls">
        <button class="chip" data-filter="all" aria-pressed="true">Все</button>
        <button class="chip" data-filter="critical" aria-pressed="false">С критичными</button>
        <button class="chip" data-filter="nohttps" aria-pressed="false">Без HTTPS</button>
        <button class="chip" data-filter="worst" aria-pressed="false">Худшие 20</button>
        <button class="chip" data-filter="stub" aria-pressed="false">Заглушки${summary.stubs ? ` (${summary.stubs})` : ''}</button>
        <input type="search" id="q" placeholder="Поиск по домену…" aria-label="Поиск по домену">
      </div>
      <div style="overflow-x:auto">
        <table>
          <thead>
            <tr>
              <th data-sort="host">Сайт</th>
              <th data-sort="overall" class="num">Итог</th>
              <th data-sort="a11y" class="num hide-sm">Доступность</th>
              <th data-sort="security" class="num hide-sm">Безопасность</th>
              <th data-sort="mobile" class="num hide-sm">Мобильный</th>
              <th data-sort="violations" class="num">Нарушений</th>
              <th data-sort="status" class="num hide-sm">HTTP</th>
            </tr>
          </thead>
          <tbody id="rows"></tbody>
        </table>
      </div>
    </div>
  </section>

  <section>
    <div class="wrap">
      <h2>Методика</h2>
      <div class="method">
        <div>
          <h3>Что проверяется</h3>
          <ul>
            <li>Главная страница в headless Chrome 1366×768</li>
            <li>axe-core, теги WCAG 2.0/2.1/2.2 A и AA</li>
            <li>TLS, редиректы, заголовки безопасности</li>
            <li>Ширина 390 px: горизонтальная прокрутка</li>
            <li>Вес страницы, DOM-узлы, число запросов</li>
          </ul>
        </div>
        <div>
          <h3>Как считается оценка</h3>
          <p>Доступность: 100 × e^(−P/100), где P — сумма штрафов 12/6/3/1 за критичное, серьёзное, умеренное и мелкое нарушение, умноженных на 1 + log₂(число элементов). Итог: 50% доступность, 25% безопасность, 15% мобильность, 10% производительность.</p>
        </div>
        <div>
          <h3>Чего здесь нет</h3>
          <p>Проверяется только главная страница. axe-core ловит около трети проблем WCAG; ручная проверка клавиатурой и скринридером остаётся необходимой. Часть сайтов блокирует дата-центры.</p>
        </div>
      </div>
    </div>
  </section>
</main>

<footer>
  <div class="wrap">
    Данные — CC BY 4.0, код — MIT. Источник списка: Certificate Transparency + ручные дополнения.
    Репозиторий: <a href="${repoUrl}">${repoUrl.replace('https://', '')}</a>.
    Сгенерировано ${new Date(summary.generatedAt).toISOString().slice(0, 16).replace('T', ' ')} UTC.
  </div>
</footer>

<script id="data" type="application/json">${payload}</script>
<script>
(function () {
  var data = JSON.parse(document.getElementById('data').textContent);
  var sites = data.sites || [];
  var summary = data.summary;
  var state = { sort: 'overall', dir: 1, filter: 'all', q: '' };

  function scoreClass(v) { return v < 60 ? 's-bad' : v < 80 ? 's-warn' : ''; }
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'})[c]; }); }
  function bar(v) {
    if (v == null) return '<div class="score"><span class="dots">—</span></div>';
    var w = Math.max(2, Math.min(100, v));
    return '<div class="score ' + scoreClass(v) + '"><span class="bar"><i style="width:' + w + '%"></i></span><b>' + v + '</b></div>';
  }

  function renderViolations() {
    var el = document.getElementById('violations');
    el.innerHTML = (summary.violations || []).slice(0, 8).map(function (v) {
      return '<a class="card" href="' + esc(v.helpUrl) + '" target="_blank" rel="noopener" style="text-decoration:none;color:inherit">' +
        '<div class="k">' + esc(v.id) + '</div>' +
        '<p>' + esc(v.help) + '</p>' +
        '<div class="m"><span class="impact ' + esc(v.impact) + '">' + esc(v.impact) + '</span> &nbsp; ' + v.sites + ' сайтов · ' + v.nodes + ' элементов</div>' +
      '</a>';
    }).join('');
  }

  function filtered() {
    var list = sites.slice();
    if (state.filter === 'critical') list = list.filter(function (s) { return !s.stub && s.impactCounts && s.impactCounts.critical > 0; });
    if (state.filter === 'nohttps') list = list.filter(function (s) { return !s.stub && s.url && s.url.indexOf('https://') !== 0; });
    if (state.filter === 'stub') list = list.filter(function (s) { return s.stub; });
    if (state.q) list = list.filter(function (s) { return s.host.indexOf(state.q) > -1; });
    list.sort(function (a, b) {
      var k = state.sort, va, vb;
      if (k === 'host' || k === 'status') { va = a[k]; vb = b[k]; }
      else if (k === 'violations') { va = (a.violations || []).length; vb = (b.violations || []).length; }
      else { va = (a.scores || {})[k]; vb = (b.scores || {})[k]; }
      if (va == null && vb == null) return 0;
      if (va == null) return 1;
      if (vb == null) return -1;
      if (typeof va === 'string') return state.dir * va.localeCompare(vb);
      return state.dir * (va - vb);
    });
    if (state.filter === 'worst') list = list.slice(0, 20);
    return list;
  }

  function render() {
    var rows = filtered();
    document.getElementById('rows').innerHTML = rows.map(function (s) {
      var sc = s.stub ? {} : (s.scores || {});
      var n = (s.violations || []).length;
      var crit = s.impactCounts && s.impactCounts.critical ? ' · ' + s.impactCounts.critical + ' крит.' : '';
      var vcol = '<span class="dots">—</span>';
      if (s.stub) vcol = '<span class="dots">заглушка</span>';
      else if (s.ok) vcol = '<span class="dots">' + n + crit + '</span>';
      else if (/^http \d+$/.test(s.error || '')) vcol = '<span class="dots">не ответил</span>';
      else if (s.error) vcol = '<span class="dots" title="' + esc(s.error) + '">' + esc(s.error).slice(0, 26) + '</span>';
      return '<tr>' +
        '<td class="host"><a href="' + esc(s.url || ('https://' + s.host)) + '" target="_blank" rel="noopener">' + esc(s.host) + '</a></td>' +
        '<td class="num"' + ((s.flags || []).length ? ' title="' + esc((s.flags || []).join(', ')) + '"' : '') + '>' + bar(sc.overall) + '</td>' +
        '<td class="num hide-sm">' + bar(sc.a11y) + '</td>' +
        '<td class="num hide-sm">' + bar(sc.security) + '</td>' +
        '<td class="num hide-sm">' + bar(sc.mobile) + '</td>' +
        '<td class="num">' + vcol + '</td>' +
        '<td class="num hide-sm"><span class="dots">' + (s.status == null ? '—' : s.status) + '</span></td>' +
      '</tr>';
    }).join('') || '<tr><td colspan="7" style="color:var(--muted)">Ничего не найдено</td></tr>';
  }

  document.querySelectorAll('th[data-sort]').forEach(function (th) {
    th.addEventListener('click', function () {
      var k = th.getAttribute('data-sort');
      if (state.sort === k) state.dir *= -1; else { state.sort = k; state.dir = 1; }
      render();
    });
  });
  document.querySelectorAll('.chip').forEach(function (btn) {
    btn.addEventListener('click', function () {
      state.filter = btn.getAttribute('data-filter');
      document.querySelectorAll('.chip').forEach(function (b) { b.setAttribute('aria-pressed', String(b === btn)); });
      render();
    });
  });
  document.getElementById('q').addEventListener('input', function (e) { state.q = e.target.value.trim().toLowerCase(); render(); });

  renderViolations();
  render();
})();
</script>
</body>
</html>
`;
}

async function main() {
  const rows = dedupe(await readResults());
  if (!rows.length) {
    console.error('no results in', RESULTS);
    process.exit(1);
  }
  const summary = summarize(rows);
  summary.sites = rows.map(compact).sort((a, b) => a.host.localeCompare(b.host));
  try {
    const discovered = JSON.parse(await fs.readFile(path.join(ROOT, 'sites.json'), 'utf8'));
    summary.discovered = discovered.total || summary.sites.length;
  } catch {
    summary.discovered = summary.sites.length;
  }

  const dateLabel = new Date(summary.generatedAt).toLocaleDateString('ru-RU', {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
  });
  const repoUrl =
    process.env.GITHUB_REPOSITORY
      ? `https://github.com/${process.env.GITHUB_REPOSITORY}`
      : 'https://github.com/matrixneoaiagent/gov-md-a11y';

  await fs.mkdir(DATA, { recursive: true });
  await fs.rm(path.join(DATA, 'site'), { recursive: true, force: true });
  await fs.mkdir(path.join(DATA, 'site'), { recursive: true });
  await fs.writeFile(path.join(DATA, 'sites.json'), JSON.stringify(summary.sites, null, 1) + '\n');
  await fs.writeFile(
    path.join(DATA, 'summary.json'),
    JSON.stringify({ ...summary, sites: undefined }, null, 2) + '\n',
  );

  for (const row of rows) {
    await fs.writeFile(
      path.join(DATA, 'site', `${row.host}.json`),
      JSON.stringify(row, null, 2) + '\n',
    );
  }

  await fs.writeFile(path.join(DOCS, 'index.html'), renderHtml(summary, dateLabel, repoUrl));
  await fs.writeFile(path.join(DOCS, 'report.md'), renderReport(summary, dateLabel));

  const pctStr = (n) => `${Math.round((n / Math.max(summary.audited, 1)) * 100)}%`;
  console.log(
    `merged ${rows.length} sites: avg ${summary.average.overall}, clean ${summary.cleanPages}, https ${pctStr(
      summary.https,
    )}, hsts ${pctStr(summary.hsts)}`,
  );
  if (process.env.GITHUB_STEP_SUMMARY) {
    await fs.appendFile(
      process.env.GITHUB_STEP_SUMMARY,
      [
        '## gov-md-a11y report',
        '',
        `- sites audited: **${summary.audited}** / ${summary.total}`,
        `- average score: **${summary.average.overall}**`,
        `- pages without WCAG violations: ${summary.cleanPages}`,
        `- https: ${pctStr(summary.https)}, valid TLS: ${pctStr(summary.tlsOk)}, HSTS: ${pctStr(summary.hsts)}`,
        '',
      ].join('\n'),
    );
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});