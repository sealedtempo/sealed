import { Hono } from 'hono';
import { html, raw } from 'hono/html';
import { bodyLimit } from 'hono/body-limit';
import { FINISHED, type Item, type Run, type RunEvent } from '../db/store.js';
import { CRAWLERS, parseJobSpec, type FieldError } from '../job.js';
import { MAX_BODY_BYTES } from './api.js';
import type { AppDeps } from './deps.js';
import { EMPTY_FORM, formToJob, readForm, type JobForm } from './form.js';
import { STYLESHEET } from './style.js';

// Server-rendered UI. No JavaScript: plain forms, and a meta refresh while a run is active.
// hono/html escapes every interpolated value, so scraped text is always rendered as text.

type Html = ReturnType<typeof html>;

const ITEMS_SHOWN = 50;
const EVENTS_SHOWN = 50;

function layout(title: string, body: Html, refresh = false): Html {
  return html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
${refresh ? raw('<meta http-equiv="refresh" content="3">') : ''}
<title>${title} - Scraper</title>
<link rel="stylesheet" href="/assets/app.css">
</head>
<body>
<header><a class="brand" href="/">Scraper</a><span class="tag">Sealed</span></header>
<main>${body}</main>
<footer>Runs inside your confidential VM. Outbound traffic only reaches destinations you approve.</footer>
</body>
</html>`;
}

const when = (d: Date | null) => (d ? d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : '-');
const badge = (status: string) => html`<span class="badge ${status}">${status}</span>`;
const active = (run: Run) => !FINISHED.has(run.status);

function errorList(errors: FieldError[]): Html | string {
  if (errors.length === 0) return '';
  return html`<div class="errors" role="alert"><p>Fix these and try again:</p><ul>${errors.map(
    (e) => html`<li><code>${e.field || 'job'}</code> ${e.message}</li>`,
  )}</ul></div>`;
}

function jobForm(form: JobForm, errors: FieldError[], crawlers: readonly string[]): Html {
  return html`<section>
<h1>New job</h1>
${errorList(errors)}
<form method="post" action="/jobs">
<label>Start URLs <small>one per line; the host names must be in this app's egress additions</small>
<textarea name="start_urls" rows="3" required placeholder="https://example.com/">${form.start_urls}</textarea></label>
<label>Fields <small>one per line as name = CSS selector; add @attr to read an attribute</small>
<textarea name="extract" rows="5" placeholder="title = h1&#10;price = .price&#10;next = a.next@href">${form.extract}</textarea></label>
<div class="row">
<label>Max pages <input type="number" name="max_pages" min="1" max="10000" value="${form.max_pages}"></label>
<label>Crawler <select name="crawler">${CRAWLERS.map(
    (c) =>
      html`<option value="${c}"${form.crawler === c ? raw(' selected') : ''}${crawlers.includes(c) ? '' : raw(' disabled')}>${c}${
        crawlers.includes(c) ? '' : ' (not in this image)'
      }</option>`,
  )}</select></label>
<label>Max concurrency <input type="number" name="max_concurrency" min="1" max="32" placeholder="default" value="${form.max_concurrency}"></label>
<label>Requests per minute <input type="number" name="max_requests_per_minute" min="1" max="1200" placeholder="60" value="${form.max_requests_per_minute}"></label>
<label>Link depth <input type="number" name="max_depth" min="0" max="100" placeholder="no limit" value="${form.max_depth}"></label>
<label>Time limit, minutes <input type="number" name="max_duration_minutes" min="1" max="1440" placeholder="no limit" value="${form.max_duration_minutes}"></label>
</div>
<label class="check"><input type="checkbox" name="same_domain"${form.same_domain ? raw(' checked') : ''}> Follow links on the same host name only</label>
<label class="check"><input type="checkbox" name="respect_robots"${form.respect_robots ? raw(' checked') : ''}> Respect robots.txt</label>
<button type="submit">Start run</button>
</form>
</section>`;
}

function runsTable(runs: Run[]): Html {
  if (runs.length === 0) return html`<section><h2>Runs</h2><p class="muted">No runs yet.</p></section>`;
  return html`<section><h2>Runs</h2>
<table><thead><tr><th>Status</th><th>Created</th><th>Crawler</th><th>Start URL</th><th class="num">Pages</th><th class="num">Failed</th><th class="num">Skipped</th></tr></thead>
<tbody>${runs.map(
    (r) => html`<tr>
<td>${badge(r.status)}</td>
<td><a href="/runs/${r.id}">${when(r.createdAt)}</a></td>
<td>${r.crawler}</td>
<td class="url">${r.spec.start_urls[0] ?? ''}${r.spec.start_urls.length > 1 ? ` (+${r.spec.start_urls.length - 1})` : ''}</td>
<td class="num">${r.pagesOk}</td><td class="num">${r.pagesFailed}</td><td class="num">${r.pagesSkipped}</td>
</tr>`,
  )}</tbody></table></section>`;
}

function itemsTable(run: Run, items: Item[]): Html {
  const fields = Object.keys(run.spec.extract);
  if (items.length === 0) return html`<p class="muted">No items yet.</p>`;
  return html`<div class="scroll"><table><thead><tr><th>URL</th>${fields.map((f) => html`<th>${f}</th>`)}</tr></thead>
<tbody>${items.map(
    (it) => html`<tr><td class="url">${it.url}</td>${fields.map((f) => html`<td>${it.data[f] ?? ''}</td>`)}</tr>`,
  )}</tbody></table></div>`;
}

function eventsTable(events: RunEvent[]): Html | string {
  if (events.length === 0) return '';
  return html`<section><h2>robots.txt, failed and skipped URLs</h2><div class="scroll"><table><thead><tr><th>Kind</th><th>URL</th><th>Detail</th></tr></thead>
<tbody>${events.map((e) => html`<tr><td>${e.kind}</td><td class="url">${e.url}</td><td>${e.detail}</td></tr>`)}</tbody></table></div></section>`;
}

function runPage(run: Run, items: Item[], events: RunEvent[]): Html {
  const actions = active(run)
    ? html`<form method="post" action="/runs/${run.id}/cancel"><button type="submit" class="secondary">Stop run</button></form>`
    : html`<form method="post" action="/runs/${run.id}/delete"><button type="submit" class="danger">Delete run</button></form>`;
  return html`<section>
<h1>Run ${badge(run.status)}</h1>
<p class="muted mono">${run.id}</p>
<dl>
<dt>Created</dt><dd>${when(run.createdAt)}</dd>
<dt>Started</dt><dd>${when(run.startedAt)}</dd>
<dt>Finished</dt><dd>${when(run.finishedAt)}</dd>
<dt>Crawler</dt><dd>${run.crawler}, up to ${run.spec.max_pages} pages, ${run.spec.max_concurrency} at a time, ${run.spec.max_requests_per_minute} per minute${
    run.spec.max_depth !== undefined ? `, link depth ${run.spec.max_depth}` : ''
  }${run.spec.max_duration_minutes !== undefined ? `, at most ${run.spec.max_duration_minutes} min` : ''}</dd>
<dt>Start URLs</dt><dd>${run.spec.start_urls.map((u) => html`<div class="url">${u}</div>`)}</dd>
<dt>Pages</dt><dd>${run.pagesOk} ok, ${run.pagesFailed} failed, ${run.pagesSkipped} skipped</dd>
${run.error ? html`<dt>Error</dt><dd>${run.error}</dd>` : ''}
</dl>
<div class="actions">
<a class="button" href="/api/v1/runs/${run.id}/export.csv">Export CSV</a>
<a class="button" href="/api/v1/runs/${run.id}/export.json">Export JSON</a>
${actions}
</div>
</section>
<section><h2>Items <small>first ${ITEMS_SHOWN}</small></h2>${itemsTable(run, items)}</section>
${eventsTable(events)}`;
}

function notFoundPage(): Html {
  return layout('Not found', html`<section><h1>Not found</h1><p><a href="/">Back to runs</a></p></section>`);
}

export function uiRoutes(deps: AppDeps): Hono {
  const ui = new Hono();
  const { store, runs, crawlers } = deps;

  const home = async (form: JobForm, errors: FieldError[]) => {
    const list = await store.listRuns({ limit: 50 });
    return layout('Runs', html`${jobForm(form, errors, crawlers)}${runsTable(list)}`);
  };

  ui.get('/assets/app.css', (c) => c.body(STYLESHEET, 200, { 'content-type': 'text/css; charset=utf-8', 'cache-control': 'max-age=3600' }));

  ui.get('/', async (c) => c.html(await home(EMPTY_FORM, [])));

  ui.post('/jobs', bodyLimit({ maxSize: MAX_BODY_BYTES }), async (c) => {
    const form = readForm(await c.req.parseBody());
    const { job, errors } = formToJob(form);
    const parsed = parseJobSpec(job, crawlers);
    if (errors.length > 0 || !parsed.ok) {
      return c.html(await home(form, [...errors, ...(parsed.ok ? [] : parsed.errors)]), 422);
    }
    const run = await runs.submit(parsed.spec);
    return c.redirect(`/runs/${run.id}`, 303);
  });

  ui.get('/runs/:id', async (c) => {
    const run = await store.getRun(c.req.param('id'));
    if (!run) return c.html(notFoundPage(), 404);
    const [items, events] = await Promise.all([
      store.listItems(run.id, { limit: ITEMS_SHOWN }),
      store.listEvents(run.id, { limit: EVENTS_SHOWN }),
    ]);
    return c.html(layout('Run', runPage(run, items, events), active(run)));
  });

  ui.post('/runs/:id/cancel', async (c) => {
    const id = c.req.param('id');
    const result = await runs.cancel(id);
    if (result === 'not-found') return c.html(notFoundPage(), 404);
    return c.redirect(`/runs/${id}`, 303);
  });

  ui.post('/runs/:id/delete', async (c) => {
    const run = await store.getRun(c.req.param('id'));
    if (!run) return c.html(notFoundPage(), 404);
    if (active(run)) return c.redirect(`/runs/${run.id}`, 303);
    await store.deleteRun(run.id);
    return c.redirect('/', 303);
  });

  return ui;
}

export { notFoundPage };
