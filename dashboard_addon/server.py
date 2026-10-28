from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import Request, urlopen
import base64
import html
import hmac
import json
import os


def service_url(name, default):
    value = os.environ.get(name, default).strip().rstrip("/")
    return value if "://" in value else "http://" + value


BROKER_BASE_URL = service_url("BROKER_URL", "http://broker:8000")
RED_BASE_URL = service_url("RED_URL", "http://red:8003")
BLUE_BASE_URL = service_url("BLUE_URL", "http://blue:8002")
LLM_BASE_URL = service_url("LLM_URL", "http://llm:8001")
DASHBOARD_URL = service_url("DASHBOARD_URL", "http://dashboard:8081") + "/"
BROKER_HEALTH_URL = BROKER_BASE_URL + "/ready"
DATABASE_HEALTH_URL = BROKER_BASE_URL + "/db-health"
BROKER_EVENTS_URL = BROKER_BASE_URL + "/events"
BROKER_STATS_URL = BROKER_BASE_URL + "/stats"
BROKER_CASES_URL = BROKER_BASE_URL + "/cases"
BROKER_RUNS_URL = BROKER_BASE_URL + "/scenario-runs"
RED_SCENARIOS_URL = RED_BASE_URL + "/scenarios"
RED_HEALTH_URL = RED_BASE_URL + "/ready"
BLUE_HEALTH_URL = BLUE_BASE_URL + "/ready"
LLM_HEALTH_URL = LLM_BASE_URL + "/ready"
BAYORA_PUBLIC_URL = os.environ.get("BAYORA_PUBLIC_URL", "http://localhost:8083").strip().rstrip("/")
BASIC_AUTH_USER = os.environ.get("DASHBOARD_BASIC_AUTH_USER", "")
BASIC_AUTH_PASSWORD = os.environ.get("DASHBOARD_BASIC_AUTH_PASSWORD", "")
PORT = int(os.environ.get("PORT", "8082"))

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>SealedArena | Security Practice Arena</title>
<style>
:root{color-scheme:dark;--bg:#090e18;--panel:#101a2a;--panel2:#131f32;--line:#26364d;--text:#edf4ff;--muted:#91a2bb;--cyan:#61d9ee;--green:#57d6a0;--red:#ff7184;--amber:#f0c36a}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 15% 0%,#142642 0,transparent 44%),var(--bg);color:var(--text);font:15px/1.5 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{width:min(1120px,calc(100% - 36px));margin:0 auto;padding:38px 0 56px}.eyebrow{margin:0 0 7px;color:var(--cyan);font-size:11px;font-weight:800;letter-spacing:.2em;text-transform:uppercase}
header{display:flex;align-items:flex-end;justify-content:space-between;gap:20px;margin-bottom:28px}h1{margin:0;font-size:clamp(28px,4vw,42px);letter-spacing:-.04em}header p{margin:7px 0 0;color:var(--muted)}
button{border:1px solid #36516f;background:#172941;color:var(--text);border-radius:10px;padding:10px 15px;font:inherit;font-weight:700;cursor:pointer}button:hover{border-color:var(--cyan);background:#1b344d}button:focus-visible{outline:2px solid var(--cyan);outline-offset:3px}
.section-title{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:30px 0 13px}.section-title h2{margin:0;font-size:16px;letter-spacing:.01em}.subtle{color:var(--muted);font-size:12px}
.health-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:12px}.service,.panel{border:1px solid var(--line);border-radius:14px;background:linear-gradient(145deg,var(--panel2),var(--panel));box-shadow:0 14px 34px #0002}.service{padding:16px}.service-head{display:flex;align-items:center;justify-content:space-between;gap:8px}.service-name{font-size:14px;font-weight:750}.pill{border-radius:99px;padding:3px 8px;font-size:10px;font-weight:850;letter-spacing:.08em;text-transform:uppercase}.pill.healthy{background:#12352f;color:var(--green)}.pill.degraded{background:#382d16;color:var(--amber)}.pill.unavailable{background:#3c2028;color:var(--red)}.detail{min-height:36px;margin:9px 0 0;color:var(--muted);font-size:12px;overflow-wrap:anywhere}
.panel{padding:16px}.notice{border-left:3px solid var(--amber);color:#dbc99f;padding:3px 0 3px 12px;font-size:13px}.event-list{display:grid;gap:10px}.event{display:grid;grid-template-columns:minmax(95px,140px) minmax(0,1fr);gap:14px;padding:13px;border:1px solid var(--line);border-radius:11px;background:#0b1422}.event-meta{color:var(--muted);font-size:12px}.event-meta strong{display:block;color:var(--text);font-size:13px}.event pre{margin:0;white-space:pre-wrap;overflow-wrap:anywhere;color:#c6d5e9;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}.empty{padding:20px;text-align:center;color:var(--muted)}.error{margin-top:12px;color:var(--red);font-size:13px}.footer{margin-top:22px;color:var(--muted);font-size:11px}.button-link{display:inline-block;border:1px solid #36516f;background:#172941;color:var(--text);border-radius:10px;padding:10px 15px;text-decoration:none;font-weight:700}
.controls{display:flex;flex-wrap:wrap;align-items:center;gap:9px;margin-bottom:14px}.controls input,.controls select{border:1px solid var(--line);background:#0b1422;color:var(--text);border-radius:9px;padding:9px 10px;font:inherit}.controls input{flex:1;min-width:190px}.controls select{min-width:135px}.controls button{padding:8px 12px}.state{display:inline-flex;align-items:center;border-radius:99px;padding:3px 8px;font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.05em}.state.pending{background:#382d16;color:var(--amber)}.state.processing{background:#18304b;color:var(--cyan)}.state.completed{background:#12352f;color:var(--green)}.state.failed{background:#3c2028;color:var(--red)}.event-body{min-width:0}.event-top{display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:9px}.event-label{color:var(--muted);font-size:11px}.event pre{margin-bottom:10px}.analysis{margin-top:10px;padding:12px;border:1px solid #2e4660;border-radius:9px;background:#111e2d}.analysis h3{margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--cyan)}.analysis p{margin:7px 0;color:#d1deef;font-size:13px;overflow-wrap:anywhere}.analysis strong{color:var(--text)}.pager{margin-left:auto;color:var(--muted);font-size:12px}.advisory{margin-top:10px}
.case-list,.run-list{display:grid;gap:12px}.case-card,.run-card{border:1px solid var(--line);border-radius:11px;background:#0b1422;padding:14px}.case-head,.run-head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}.case-head h3,.run-head strong{margin:0;font-size:14px}.case-meta,.case-evidence,.activity{margin:7px 0;color:var(--muted);font-size:12px}.case-controls{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:8px;margin-top:12px}.case-controls input,.case-controls select,.case-controls textarea{width:100%;border:1px solid var(--line);border-radius:8px;background:#101a2a;color:var(--text);padding:8px;font:inherit}.case-controls textarea{min-height:42px;resize:vertical}.case-controls button{align-self:end}.case-evidence{padding:8px;border-left:2px solid #36516f}.danger{border-color:#804354;color:#ffdbe0}.run-card{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}.status-message{min-height:22px;margin:4px 0 12px;color:var(--muted);font-size:13px}
@media(max-width:600px){main{width:min(100% - 24px,1120px);padding-top:24px}header{align-items:flex-start;flex-direction:column}.event{grid-template-columns:1fr;gap:5px}}
</style>
</head>
<body>
<main>
  <header>
    <div><p class="eyebrow">Local security practice arena</p><h1>SealedArena</h1><p>Synthetic scenarios, evidence-backed detections, and analyst cases</p></div>
    <div class="controls"><a class="button-link" href="http://localhost:8083/">Bayora Lab</a><button id="refresh" type="button">Refresh now</button></div>
  </header>
  <section aria-labelledby="health-heading">
    <div class="section-title"><h2 id="health-heading">Service health</h2><span id="updated" class="subtle">Connecting…</span></div>
    <div id="services" class="health-grid" aria-live="polite"></div>
  </section>
  <section aria-labelledby="metrics-heading">
    <div class="section-title"><h2 id="metrics-heading">Queue and case counts</h2><span class="subtle">Current database totals</span></div>
    <div id="metrics" class="health-grid" aria-live="polite"></div>
  </section>
  <section aria-labelledby="scenario-heading">
    <div class="section-title"><h2 id="scenario-heading">Run a synthetic scenario</h2><span class="subtle">Safe demo telemetry · no real systems are contacted</span></div>
    <div class="panel">
      <div class="controls">
        <select id="scenario-select" aria-label="Select a scenario"></select>
        <button id="run-scenario" type="button">Run scenario</button>
        <button id="reset-scenarios" class="danger" type="button">Clear synthetic data</button>
      </div>
      <p id="scenario-message" class="status-message" role="status"></p>
      <div id="scenario-runs" class="run-list"></div>
    </div>
  </section>
  <section aria-labelledby="cases-heading">
    <div class="section-title"><h2 id="cases-heading">Analyst cases</h2><span class="subtle">Review findings, record a verdict, and add notes</span></div>
    <div class="controls">
      <input id="case-search" type="search" placeholder="Search cases" aria-label="Search cases">
      <select id="case-status-filter" aria-label="Filter cases by status"><option value="">All case states</option><option value="new">New</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option></select>
      <select id="case-severity-filter" aria-label="Filter cases by severity"><option value="">All case severities</option><option>informational</option><option>low</option><option>medium</option><option>high</option><option>critical</option></select>
    </div>
    <div id="cases" class="case-list" aria-live="polite"><div class="empty">Loading cases…</div></div>
  </section>
  <section aria-labelledby="events-heading">
    <div class="section-title"><h2 id="events-heading">Events and analysis</h2><span class="subtle">Newest first · refreshes every 3 seconds</span></div>
    <div class="panel">
      <div class="controls">
        <input id="event-search" type="search" placeholder="Search event payloads" aria-label="Search events">
        <select id="status-filter" aria-label="Filter by processing status"><option value="">All statuses</option><option>pending</option><option>processing</option><option>completed</option><option>failed</option></select>
        <select id="severity-filter" aria-label="Filter by analysis severity"><option value="">All severities</option><option>informational</option><option>low</option><option>medium</option><option>high</option><option>critical</option><option>unknown</option></select>
        <select id="scenario-filter" aria-label="Filter by scenario"><option value="">All scenario runs</option></select>
        <input id="source-filter" type="search" placeholder="Filter source" aria-label="Filter by source">
        <input id="asset-filter" type="search" placeholder="Filter user or device" aria-label="Filter by user or device">
        <button id="previous-page" type="button">Previous</button>
        <button id="next-page" type="button">Next</button>
        <span id="page-info" class="pager">Loading…</span>
      </div>
      <div id="events" class="event-list" aria-live="polite"><div class="empty">Loading events…</div></div>
      <div id="events-error" class="error" role="status"></div>
    </div>
  </section>
  <section aria-labelledby="analysis-heading">
    <div class="section-title"><h2 id="analysis-heading">Analysis results</h2></div>
    <div class="panel"><div class="notice">Analysis is advisory. Recommendations are displayed for human review and are never executed automatically.</div></div>
  </section>
  <p class="footer">Synthetic training data only · served locally on port 8082</p>
</main>
<script>
const servicesNode = document.getElementById('services');
const metricsNode = document.getElementById('metrics');
const eventsNode = document.getElementById('events');
const eventsErrorNode = document.getElementById('events-error');
const updatedNode = document.getElementById('updated');
const pageInfoNode = document.getElementById('page-info');
const previousButton = document.getElementById('previous-page');
const nextButton = document.getElementById('next-page');
const pageSize = 20;
let eventOffset = 0;
let eventTotal = 0;
let searchTimer = null;
const caseDrafts = new Map();

function setOptions(select, firstLabel, items, valueOf, labelOf) {
  const selected = select.value;
  const options = [new Option(firstLabel, ''), ...items.map(item => new Option(labelOf(item), valueOf(item)))];
  select.replaceChildren(...options);
  if ([...select.options].some(option => option.value === selected)) select.value = selected;
}

function renderScenarioControls(snapshot) {
  const scenarioSelect = document.getElementById('scenario-select');
  const scenarioFilter = document.getElementById('scenario-filter');
  setOptions(scenarioSelect, 'Choose a scenario…', snapshot.scenarios || [], item => item.id, item => item.title);
  setOptions(scenarioFilter, 'All scenario runs', snapshot.scenario_runs || [], item => item.run_id,
    item => item.name + ' · ' + item.run_id.slice(0, 8));
  const runsNode = document.getElementById('scenario-runs');
  const runs = snapshot.scenario_runs || [];
  if (!runs.length) {
    runsNode.replaceChildren(Object.assign(document.createElement('div'), {className: 'empty', textContent: 'No scenarios have been run yet.'}));
    return;
  }
  runsNode.replaceChildren(...runs.slice(0, 5).map(run => {
    const card = document.createElement('div');
    card.className = 'run-card';
    const title = document.createElement('strong');
    title.textContent = run.name;
    const details = document.createElement('span');
    details.className = 'subtle';
    details.textContent = run.event_count + ' events · ' + run.status + ' · ' + formatTime(run.started_at);
    card.append(title, details);
    return card;
  }));
}

function renderCases(cases) {
  const casesNode = document.getElementById('cases');
  if (!cases.length) {
    casesNode.replaceChildren(Object.assign(document.createElement('div'), {className: 'empty', textContent: 'No cases match these filters, or no detections have been created yet.'}));
    return;
  }
  casesNode.replaceChildren(...cases.map(caseItem => {
    const card = document.createElement('article');
    card.className = 'case-card';
    const head = document.createElement('div');
    head.className = 'case-head';
    const title = document.createElement('h3');
    title.textContent = '#' + caseItem.id + ' · ' + caseItem.title;
    const severity = document.createElement('span');
    severity.className = 'state ' + (caseItem.severity === 'high' || caseItem.severity === 'critical' ? 'failed' : 'processing');
    severity.textContent = caseItem.severity;
    head.append(title, severity);
    const meta = document.createElement('p');
    meta.className = 'case-meta';
    meta.textContent = caseItem.event_count + ' linked event(s) · ' + caseItem.status.replace('_', ' ') + ' · ' + caseItem.verdict.replaceAll('_', ' ') + (caseItem.assigned_to ? ' · assigned to ' + caseItem.assigned_to : ' · unassigned');
    const evidence = document.createElement('div');
    evidence.className = 'case-evidence';
    const evidenceItems = [];
    for (const event of (caseItem.events || [])) {
      const payload = event.payload || {};
      const findings = (event.detections || []).filter(item => item && item.rule_id && caseItem.case_key.endsWith(':' + item.rule_id));
      if (findings.length) evidenceItems.push('Event #' + event.id + ' · ' + (payload.event_type || event.type) + ' · ' + findings.map(item => item.summary).join('; '));
      else evidenceItems.push('Event #' + event.id + ' · ' + (payload.event_type || event.type));
    }
    evidence.textContent = evidenceItems.join('\\n') || 'Evidence details are unavailable.';
    const activity = document.createElement('p');
    activity.className = 'activity';
    activity.textContent = (caseItem.recent_activity || []).map(item => {
      const detail = item.detail || {};
      return item.action === 'note_added' ? (item.actor + ' note: ' + detail.note) : (item.actor + ' · ' + item.action.replaceAll('_', ' '));
    }).join(' | ') || 'No analyst activity recorded yet.';
    const controls = document.createElement('div');
    controls.className = 'case-controls';
    const status = document.createElement('select');
    status.setAttribute('aria-label', 'Case status');
    for (const value of ['new', 'investigating', 'resolved']) status.add(new Option(value.replace('_', ' '), value));
    const draft = caseDrafts.get(String(caseItem.id)) || {};
    status.value = draft.status || caseItem.status;
    const verdict = document.createElement('select');
    verdict.setAttribute('aria-label', 'Analyst verdict');
    for (const value of ['unreviewed', 'true_positive', 'false_positive', 'needs_more_info']) verdict.add(new Option(value.replaceAll('_', ' '), value));
    verdict.value = draft.verdict || caseItem.verdict;
    const assigned = document.createElement('input');
    assigned.setAttribute('aria-label', 'Assigned analyst');
    assigned.placeholder = 'Assign to analyst';
    assigned.value = draft.assigned_to ?? caseItem.assigned_to ?? '';
    const note = document.createElement('textarea');
    note.setAttribute('aria-label', 'Analyst note');
    note.placeholder = 'Add an investigation note';
    note.value = draft.note || '';
    const saveDraft = () => caseDrafts.set(String(caseItem.id), {
      status: status.value, verdict: verdict.value, assigned_to: assigned.value, note: note.value
    });
    status.addEventListener('change', saveDraft);
    verdict.addEventListener('change', saveDraft);
    assigned.addEventListener('input', saveDraft);
    note.addEventListener('input', saveDraft);
    const save = document.createElement('button');
    save.type = 'button';
    save.textContent = 'Save review';
    const feedback = document.createElement('span');
    feedback.className = 'subtle';
    save.addEventListener('click', async () => {
      save.disabled = true;
      feedback.textContent = 'Saving…';
      try {
        const response = await fetch('/api/cases/update', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({case_id: caseItem.id, status: status.value, verdict: verdict.value, assigned_to: assigned.value, note: note.value})
        });
        if (!response.ok) throw new Error('Case update failed (' + response.status + ')');
        caseDrafts.delete(String(caseItem.id));
        note.value = '';
        feedback.textContent = 'Saved';
        await refresh();
      } catch (error) {
        feedback.textContent = String(error);
      } finally {
        save.disabled = false;
      }
    });
    controls.append(status, verdict, assigned, note, save, feedback);
    card.append(head, meta, evidence, activity, controls);
    return card;
  }));
}

function renderServices(services) {
  servicesNode.replaceChildren(...services.map(service => {
    const card = document.createElement('article');
    card.className = 'service';
    const head = document.createElement('div');
    head.className = 'service-head';
    const name = document.createElement('span');
    name.className = 'service-name';
    name.textContent = service.name;
    const badge = document.createElement('span');
    badge.className = 'pill ' + (service.status || 'unavailable');
    badge.textContent = service.status || 'unavailable';
    const detail = document.createElement('p');
    detail.className = 'detail';
    detail.textContent = service.detail || '';
    head.append(name, badge);
    card.append(head, detail);
    return card;
  }));
}

function renderMetrics(metrics) {
  const eventCounts = metrics.events || {};
  const caseCounts = metrics.cases || {};
  const tiles = [
    ['Pending events', eventCounts.pending || 0],
    ['Processing events', eventCounts.processing || 0],
    ['Failed events', eventCounts.failed || 0],
    ['Open cases', (caseCounts.new || 0) + (caseCounts.investigating || 0)],
    ['Scenario runs', metrics.scenario_runs || 0],
  ];
  metricsNode.replaceChildren(...tiles.map(([label, count]) => {
    const card = document.createElement('article');
    card.className = 'service';
    const title = document.createElement('div');
    title.className = 'service-name';
    title.textContent = label;
    const value = document.createElement('p');
    value.className = 'detail';
    value.textContent = String(count);
    card.append(title, value);
    return card;
  }));
}

function formatTime(value) {
  if (!value) return 'Time unavailable';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function renderEvents(events) {
  if (!events.length) {
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = 'No events have been recorded yet.';
    eventsNode.replaceChildren(empty);
    return;
  }
  eventsNode.replaceChildren(...events.map(event => {
    const row = document.createElement('article');
    row.className = 'event';
    const meta = document.createElement('div');
    meta.className = 'event-meta';
    const id = document.createElement('strong');
    id.textContent = 'Event #' + (event.id ?? 'unknown');
    const time = document.createElement('span');
    time.textContent = formatTime(event.received_at);
    const origin = document.createElement('span');
    origin.textContent = (event.source || event.payload?.source || 'unknown') + ' · ' + (event.type || event.payload?.type || 'event');
    meta.append(id, time, document.createElement('br'), origin);
    if (event.scenario_run_id) {
      const run = document.createElement('span');
      run.textContent = 'Scenario run · ' + event.scenario_run_id.slice(0, 8);
      meta.append(document.createElement('br'), run);
    }
    const body = document.createElement('div');
    body.className = 'event-body';
    const top = document.createElement('div');
    top.className = 'event-top';
    const state = document.createElement('span');
    state.className = 'state ' + (event.status || 'completed');
    state.textContent = event.status || 'completed';
    const attempt = document.createElement('span');
    attempt.className = 'event-label';
    attempt.textContent = 'Attempts: ' + (event.attempts ?? 0);
    top.append(state, attempt);
    const payload = document.createElement('pre');
    payload.textContent = JSON.stringify(event.payload ?? {}, null, 2);
    body.append(top, payload);
    if (event.analysis) {
      const analysis = document.createElement('div');
      analysis.className = 'analysis';
      const heading = document.createElement('h3');
      heading.textContent = 'Analysis · ' + (event.analysis.severity || 'unknown');
      const explanation = document.createElement('p');
      explanation.textContent = event.analysis.explanation || 'No explanation provided.';
      const confidence = document.createElement('p');
      confidence.textContent = 'Confidence: ' + (event.analysis.confidence == null ? 'not provided' : Math.round(event.analysis.confidence * 100) + '%');
      const recommendation = document.createElement('p');
      recommendation.textContent = 'Recommendation: ' + (event.analysis.recommendation || 'No recommendation provided.');
      const model = document.createElement('p');
      model.textContent = 'Provider/model: ' + (event.analysis.provider || 'unknown') + ' / ' + (event.analysis.model || 'unknown') + ' · ' + formatTime(event.analysis.analyzed_at);
      const mode = document.createElement('p');
      mode.textContent = 'Analysis mode: ' + (event.analysis.analysis_mode || 'unknown') + (event.analysis.provider === 'mock' ? ' · mock output is not a real model assessment' : '');
      const suggested = document.createElement('p');
      suggested.textContent = 'AI-suggested severity (unverified): ' + (event.analysis.ai_suggested_severity || 'unknown');
      analysis.append(heading, mode, explanation, confidence, recommendation, suggested, model);
      for (const finding of (event.analysis.detections || [])) {
        const detection = document.createElement('p');
        detection.textContent = 'Rule ' + finding.rule_id + ' · ' + finding.summary + ' · evidence events: ' + (finding.evidence || []).map(item => '#' + item.event_id).filter(Boolean).join(', ');
        analysis.append(detection);
      }
      if (event.analysis.ai_summary) {
        const ai = document.createElement('p');
        ai.textContent = 'AI-generated context (unverified): ' + event.analysis.ai_summary;
        analysis.append(ai);
      }
      if (event.analysis.ai_recommendation) {
        const aiRecommendation = document.createElement('p');
        aiRecommendation.textContent = 'AI-generated recommendation (unverified): ' + event.analysis.ai_recommendation;
        analysis.append(aiRecommendation);
      }
      body.append(analysis);
    } else {
      const note = document.createElement('p');
      note.className = 'event-label advisory';
      if (event.legacy_import) {
        note.textContent = 'Historical event preserved; its earlier analysis was only in logs and was not retained.';
      } else if (event.status === 'failed') {
        note.textContent = 'Processing failed: ' + (event.last_error || 'No error detail available.');
      } else {
        note.textContent = 'Analysis has not been stored yet.';
      }
      body.append(note);
      if (event.status === 'failed') {
        const retry = document.createElement('button');
        retry.type = 'button';
        retry.textContent = 'Retry analysis';
        retry.addEventListener('click', () => retryEvent(event.id, retry));
        body.append(retry);
      }
    }
    row.append(meta, body);
    return row;
  }));
}

async function refresh() {
  try {
    const params = new URLSearchParams({limit: String(pageSize), offset: String(eventOffset)});
    const query = document.getElementById('event-search').value.trim();
    const status = document.getElementById('status-filter').value;
    const severity = document.getElementById('severity-filter').value;
    const scenarioRunId = document.getElementById('scenario-filter').value;
    const source = document.getElementById('source-filter').value.trim();
    const asset = document.getElementById('asset-filter').value.trim();
    const caseStatus = document.getElementById('case-status-filter').value;
    const caseSeverity = document.getElementById('case-severity-filter').value;
    const caseQuery = document.getElementById('case-search').value.trim();
    if (query) params.set('q', query);
    if (status) params.set('status', status);
    if (severity) params.set('severity', severity);
    if (scenarioRunId) params.set('scenario_run_id', scenarioRunId);
    if (source) params.set('source', source);
    if (asset) params.set('asset', asset);
    if (caseStatus) params.set('case_status', caseStatus);
    if (caseSeverity) params.set('case_severity', caseSeverity);
    if (caseQuery) params.set('case_q', caseQuery);
    const response = await fetch('/api/dashboard?' + params.toString(), {cache: 'no-store'});
    if (!response.ok) throw new Error('Dashboard request failed (' + response.status + ')');
    const snapshot = await response.json();
    renderScenarioControls(snapshot);
    renderCases(snapshot.cases || []);
    renderServices(snapshot.services || []);
    renderMetrics(snapshot.metrics || {});
    renderEvents(snapshot.events || []);
    eventsErrorNode.textContent = snapshot.events_error || '';
    eventTotal = snapshot.total || 0;
    const shownStart = eventTotal === 0 ? 0 : eventOffset + 1;
    const shownEnd = Math.min(eventOffset + (snapshot.events || []).length, eventTotal);
    pageInfoNode.textContent = 'Showing ' + shownStart + '–' + shownEnd + ' of ' + eventTotal;
    previousButton.disabled = eventOffset <= 0;
    nextButton.disabled = eventOffset + pageSize >= eventTotal;
    updatedNode.textContent = 'Updated ' + new Date(snapshot.generated_at).toLocaleTimeString();
  } catch (error) {
    updatedNode.textContent = 'Refresh failed';
    eventsErrorNode.textContent = String(error);
  }
}

async function retryEvent(eventId, button) {
  button.disabled = true;
  button.textContent = 'Retrying…';
  try {
    const response = await fetch('/api/events/retry', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({event_id: eventId})
    });
    if (!response.ok) throw new Error('Retry request failed (' + response.status + ')');
    await refresh();
  } catch (error) {
    eventsErrorNode.textContent = String(error);
    button.disabled = false;
    button.textContent = 'Retry analysis';
  }
}

async function runScenario() {
  const button = document.getElementById('run-scenario');
  const message = document.getElementById('scenario-message');
  const scenarioId = document.getElementById('scenario-select').value;
  if (!scenarioId) { message.textContent = 'Choose a scenario first.'; return; }
  button.disabled = true;
  button.textContent = 'Generating…';
  message.textContent = 'Creating synthetic events and waiting for the simulator…';
  try {
    const response = await fetch('/api/scenarios/run', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({scenario_id: scenarioId})
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Scenario failed (' + response.status + ')');
    message.textContent = result.scenario_name + ' created ' + result.event_count + ' synthetic event(s). Run ' + result.run_id.slice(0, 8) + '.';
    await refresh();
  } catch (error) {
    message.textContent = String(error);
  } finally {
    button.disabled = false;
    button.textContent = 'Run scenario';
  }
}

async function resetSyntheticData() {
  const message = document.getElementById('scenario-message');
  if (!window.confirm('Permanently clear all scenario-generated events, cases, and run history? This cannot be undone.')) return;
  try {
    const response = await fetch('/api/scenarios/reset', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({confirm: 'clear-synthetic-data'})
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Reset failed (' + response.status + ')');
    message.textContent = 'Cleared ' + result.events_deleted + ' synthetic events, ' + result.cases_deleted + ' cases, and ' + result.runs_deleted + ' runs.';
    eventOffset = 0;
    await refresh();
  } catch (error) {
    message.textContent = String(error);
  }
}

document.getElementById('refresh').addEventListener('click', refresh);
document.getElementById('run-scenario').addEventListener('click', runScenario);
document.getElementById('reset-scenarios').addEventListener('click', resetSyntheticData);
previousButton.addEventListener('click', () => { eventOffset = Math.max(0, eventOffset - pageSize); refresh(); });
nextButton.addEventListener('click', () => { if (eventOffset + pageSize < eventTotal) { eventOffset += pageSize; refresh(); } });
document.getElementById('status-filter').addEventListener('change', () => { eventOffset = 0; refresh(); });
document.getElementById('severity-filter').addEventListener('change', () => { eventOffset = 0; refresh(); });
document.getElementById('scenario-filter').addEventListener('change', () => { eventOffset = 0; refresh(); });
document.getElementById('source-filter').addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { eventOffset = 0; refresh(); }, 300);
});
document.getElementById('asset-filter').addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { eventOffset = 0; refresh(); }, 300);
});
document.getElementById('case-status-filter').addEventListener('change', refresh);
document.getElementById('case-severity-filter').addEventListener('change', refresh);
document.getElementById('case-search').addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(refresh, 300);
});
document.getElementById('event-search').addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { eventOffset = 0; refresh(); }, 300);
});
refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>""".encode("utf-8")


def read_json(url):
    with urlopen(url, timeout=2) as response:
        return json.loads(response.read().decode("utf-8"))


def probe_json_service(name, url):
    try:
        data = read_json(url)
        if not isinstance(data, dict):
            raise ValueError("health endpoint returned a non-object response")
        reported_status = data.get("status")
        status = "healthy" if reported_status == "healthy" else "degraded"
        detail = f"{data.get('service', name)} reports {reported_status or 'no status'}"
        if data.get("storage"):
            detail += f" · {data['storage']}"
        if data.get("provider"):
            detail += f" · {data['provider']} / {data.get('model', 'configured')}"
        return {"name": name, "status": status, "detail": detail}
    except (OSError, URLError, ValueError, json.JSONDecodeError) as error:
        return {
            "name": name,
            "status": "unavailable",
            "detail": f"Health check failed: {error}",
        }


def probe_dashboard():
    try:
        with urlopen(DASHBOARD_URL, timeout=2) as response:
            response.read(128)
            return {
                "name": "Dashboard",
                "status": "healthy",
                "detail": f"Page responded with HTTP {response.status}",
            }
    except (OSError, URLError, ValueError) as error:
        return {
            "name": "Dashboard",
            "status": "unavailable",
            "detail": f"Page check failed: {error}",
        }


def read_events(params):
    try:
        query = urlencode({key: value for key, value in params.items() if value not in (None, "")})
        data = read_json(BROKER_EVENTS_URL + ("?" + query if query else ""))
        events = data.get("events") if isinstance(data, dict) else None
        if not isinstance(events, list):
            raise ValueError("events endpoint did not return an events list")
        return events, int(data.get("total", len(events))), None
    except (OSError, URLError, ValueError, json.JSONDecodeError) as error:
        return [], 0, f"Could not load events: {error}"


def read_status_counts():
    try:
        data = read_json(BROKER_STATS_URL)
        return data.get("metrics", {}) if isinstance(data, dict) else {}
    except (OSError, URLError, ValueError, json.JSONDecodeError):
        return {}


def read_cases(params=None):
    try:
        params = params or {}
        query = urlencode({
            "limit": 50,
            "status": params.get("case_status", ""),
            "severity": params.get("case_severity", ""),
            "q": params.get("case_q", ""),
        })
        data = read_json(BROKER_CASES_URL + "?" + query)
        return data.get("cases", []) if isinstance(data, dict) else []
    except (OSError, URLError, ValueError, json.JSONDecodeError):
        return []


def read_scenario_runs():
    try:
        data = read_json(BROKER_RUNS_URL + "?limit=10")
        return data.get("runs", []) if isinstance(data, dict) else []
    except (OSError, URLError, ValueError, json.JSONDecodeError):
        return []


def read_scenarios():
    try:
        data = read_json(RED_SCENARIOS_URL)
        return data.get("scenarios", []) if isinstance(data, dict) else []
    except (OSError, URLError, ValueError, json.JSONDecodeError):
        return []


def collect_snapshot(params=None):
    params = params or {}
    checks = [
        ("Broker", lambda: probe_json_service("Broker", BROKER_HEALTH_URL)),
        ("PostgreSQL", lambda: probe_json_service("PostgreSQL", DATABASE_HEALTH_URL)),
        ("Red Simulator", lambda: probe_json_service("Red Simulator", RED_HEALTH_URL)),
        ("Blue Team", lambda: probe_json_service("Blue Team", BLUE_HEALTH_URL)),
        ("LLM", lambda: probe_json_service("LLM", LLM_HEALTH_URL)),
        ("Dashboard", probe_dashboard),
    ]
    event_params = {
        "limit": max(1, min(int(params.get("limit", 25)), 100)),
        "offset": max(0, min(int(params.get("offset", 0)), 100000)),
        "status": params.get("status"),
        "severity": params.get("severity"),
        "q": params.get("q"),
        "scenario_run_id": params.get("scenario_run_id"),
        "source": params.get("source"),
        "asset": params.get("asset"),
    }
    with ThreadPoolExecutor(max_workers=len(checks) + 5) as executor:
        futures = [(name, executor.submit(check)) for name, check in checks]
        events_future = executor.submit(read_events, event_params)
        counts_future = executor.submit(read_status_counts)
        cases_future = executor.submit(read_cases, params)
        runs_future = executor.submit(read_scenario_runs)
        scenarios_future = executor.submit(read_scenarios)
        services = []
        for name, future in futures:
            try:
                services.append(future.result())
            except Exception as error:
                services.append({
                    "name": name,
                    "status": "unavailable",
                    "detail": f"Health check failed: {error}",
                })
        try:
            events, total, events_error = events_future.result()
        except Exception as error:
            events, total, events_error = [], 0, f"Could not load events: {error}"
        try:
            counts = counts_future.result()
        except Exception:
            counts = {}
        cases = cases_future.result()
        runs = runs_future.result()
        scenarios = scenarios_future.result()

    services.append({
        "name": "Dashboard add-on",
        "status": "healthy",
        "detail": "This page is being served successfully",
    })
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "services": services,
        "events": events,
        "total": total,
        "limit": event_params["limit"],
        "offset": event_params["offset"],
        "status_counts": counts,
        "metrics": counts,
        "cases": cases,
        "scenario_runs": runs,
        "scenarios": scenarios,
        "events_error": events_error,
    }


class DashboardAddonHandler(BaseHTTPRequestHandler):
    def require_auth(self):
        if not BASIC_AUTH_USER and not BASIC_AUTH_PASSWORD:
            return True
        expected = "Basic " + base64.b64encode(
            f"{BASIC_AUTH_USER}:{BASIC_AUTH_PASSWORD}".encode("utf-8")
        ).decode("ascii")
        supplied = self.headers.get("Authorization", "")
        if hmac.compare_digest(supplied, expected):
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="SealedArena demo"')
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        return False

    def send_body(self, status, content_type, body):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_body(status, "application/json; charset=utf-8", body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path not in {"/health", "/ready"} and not self.require_auth():
            return
        if path == "/":
            page = PAGE.replace(
                'href="http://localhost:8083/"',
                'href="' + html.escape(BAYORA_PUBLIC_URL, quote=True) + '/"',
            ).encode("utf-8")
            self.send_body(200, "text/html; charset=utf-8", page)
        elif path == "/health":
            self.send_json(200, {"service": "dashboard-addon", "status": "healthy"})
        elif path == "/ready":
            snapshot = collect_snapshot({"limit": 1, "offset": 0})
            required = {"Broker", "PostgreSQL", "Red Simulator", "Blue Team", "Dashboard"}
            by_name = {item["name"]: item for item in snapshot["services"]}
            ready = all(by_name.get(name, {}).get("status") == "healthy" for name in required)
            self.send_json(200 if ready else 503, {
                "service": "dashboard-addon",
                "status": "healthy" if ready else "unavailable",
                "dependencies": {name: by_name.get(name, {}).get("status", "unknown") for name in sorted(required)},
            })
        elif path == "/api/dashboard":
            params = parse_qs(urlsplit(self.path).query)
            values = {key: value[0] for key, value in params.items() if value}
            try:
                self.send_json(200, collect_snapshot(values))
            except ValueError:
                self.send_json(400, {"error": "limit and offset must be integers"})
        else:
            self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        if not self.require_auth():
            return
        path = urlsplit(self.path).path
        destinations = {
            "/api/events/retry": BROKER_BASE_URL + "/events/retry",
            "/api/cases/update": BROKER_BASE_URL + "/cases/update",
            "/api/scenarios/run": RED_BASE_URL + "/scenarios/run",
            "/api/scenarios/reset": BROKER_BASE_URL + "/scenario-runs/reset",
        }
        if path not in destinations:
            self.send_json(404, {"error": "Not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 8192:
                self.send_json(400, {"error": "Invalid body size"})
                return
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                self.send_json(400, {"error": "JSON object required"})
                return
            if path == "/api/events/retry":
                event_id = data.get("event_id")
                if isinstance(event_id, bool) or not isinstance(event_id, int) or event_id < 1:
                    self.send_json(400, {"error": "event_id must be a positive integer"})
                    return
            elif path == "/api/cases/update":
                case_id = data.get("case_id")
                if isinstance(case_id, bool) or not isinstance(case_id, int) or case_id < 1:
                    self.send_json(400, {"error": "case_id must be a positive integer"})
                    return
            elif path == "/api/scenarios/run":
                if not isinstance(data.get("scenario_id"), str):
                    self.send_json(400, {"error": "scenario_id is required"})
                    return
            elif data.get("confirm") != "clear-synthetic-data":
                self.send_json(400, {"error": "explicit confirmation is required"})
                return
            request = Request(
                destinations[path],
                data=json.dumps(data).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(request, timeout=10) as response:
                body = json.loads(response.read().decode("utf-8"))
                self.send_json(response.status, body)
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": str(error)})
        except HTTPError as error:
            try:
                body = json.loads(error.read().decode("utf-8"))
            except Exception:
                body = {"error": "Request failed"}
            self.send_json(error.code, body)
        except Exception as error:
            try:
                self.send_json(503, {"error": "Request could not be completed"})
            except Exception:
                pass

    def log_message(self, format_string, *args):
        print(json.dumps({
            "service": "dashboard-addon",
            "stage": "http_request",
            "client": self.address_string(),
            "route": urlsplit(self.path).path,
        }), flush=True)


server = ThreadingHTTPServer(("0.0.0.0", PORT), DashboardAddonHandler)
server.daemon_threads = True
print(f"[DASHBOARD-ADDON] Listening on port {PORT}", flush=True)
server.serve_forever()
