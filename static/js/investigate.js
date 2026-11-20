(() => {
  'use strict';

  let mode = 'URL';
  const input = document.getElementById('investigator-input');
  const fileInput = document.getElementById('file-input');
  const selectFile = document.getElementById('file-select');
  const form = document.getElementById('investigate-form');
  const result = document.getElementById('investigation-result');
  const analyzeButton = document.getElementById('analyze-btn');

  if (!input || !fileInput || !selectFile || !form || !result || !analyzeButton) {
    console.error('[CTI Sentinel] Investigation page controls are missing.');
    return;
  }

  const esc = value => CTI.escape(value);
  const showError = message => {
    result.innerHTML = `<div class="notice error"><b>Analysis could not be completed.</b><br>${esc(message)}</div>`;
  };

  function updateOptions() {
    document.getElementById('deep-vt-scan').parentElement.style.display = mode === 'URL' ? 'flex' : 'none';
    document.getElementById('refresh-vt-analysis').parentElement.style.display = mode === 'IP' ? 'flex' : 'none';
    document.querySelector('.sandbox-option').style.display = mode === 'FILE' ? 'flex' : 'none';
    selectFile.hidden = mode !== 'FILE';
    input.hidden = mode === 'FILE';
    analyzeButton.textContent = mode === 'FILE' ? 'Analyze File →' : 'Analyze →';
    input.autocomplete = 'off';
  }

  document.querySelectorAll('.mode').forEach(button => {
    button.type = 'button';
    button.addEventListener('click', () => {
      document.querySelectorAll('.mode').forEach(item => item.classList.remove('active'));
      button.classList.add('active');
      mode = button.dataset.mode;
      input.placeholder = button.dataset.placeholder || 'Enter an indicator';
      if (mode === 'URL' && !input.value.trim()) input.value = 'https://example.com';
      if (mode !== 'URL') input.value = '';
      selectFile.textContent = 'Select file ＋';
      fileInput.value = '';
      updateOptions();
      result.replaceChildren();
    });
  });

  selectFile.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => {
    const file = fileInput.files && fileInput.files[0];
    selectFile.innerHTML = file ? `${esc(file.name)} <b>✓</b>` : 'Select file <b>＋</b>';
  });

  function sourceCards(sources) {
    return Object.entries(sources || {}).map(([name, item]) => {
      const matched = Boolean(item.match);
      const failed = item.status === 'error' || Boolean(item.error);
      const state = matched ? 'MATCH' : failed ? 'ERROR' : item.configured === false ? 'NOT CONFIGURED' : 'NO MATCH';
      return `<div class="source-evidence">
        <b>${esc(name)}</b>
        <span class="source-state ${matched ? 'match' : failed ? 'error' : 'none'}">${state}</span>
        <small>${esc(item.message || item.error || (item.configured === false ? 'Provider credentials are not configured.' : 'No matching indicator returned.'))}</small>
      </div>`;
    }).join('');
  }

  function modelCard(data) {
    if (data.indicator_type !== 'url' || !data.ml_status) return '';
    const pct = value => value !== null && value !== undefined && Number.isFinite(Number(value))
      ? `${(Number(value) * 100).toFixed(1)}%` : '—';
    return `<div class="result-section ml-result">
      <div class="ml-result-heading">
        <div><h3>CTI Sentinel URL ML</h3><small>Independent character-level URL classifier · ${esc(data.ml_model || '')}</small></div>
        <span class="ml-status ${esc(data.ml_status)}">${esc(String(data.ml_status).toUpperCase())}</span>
      </div>
      <div class="detail-grid">
        <div><small>MODEL PREDICTION</small><b>${esc(data.ml_prediction || 'NOT AVAILABLE')}</b></div>
        <div><small>PREDICTED-CLASS SCORE</small><b>${pct(data.ml_confidence)}</b></div>
        <div><small>MALICIOUS SCORE</small><b>${pct(data.ml_malicious_probability)}</b></div>
        <div><small>DECISION THRESHOLD</small><b>${pct(data.ml_decision_threshold)}</b></div>
      </div>
      <p class="ml-disclaimer">${esc(data.ml_message || 'Independent model signal; not blended into the legacy CTI threat score.')}</p>
    </div>`;
  }

  function render(data) {
    const level = String(data.threat_level || 'unknown').toLowerCase();
    const sources = data.source_results || data.cti?.source_results || {};
    const sourceMarkup = sourceCards(sources);
    const errors = (data.errors || []).map(error => `<div class="notice warning">${esc(error)}</div>`).join('');
    const reportLink = data.report_id
      ? `<a class="primary-btn" href="/reports/${encodeURIComponent(data.report_id)}">Open full report →</a>`
      : '';
    result.innerHTML = `<section class="panel result-panel">
      <div class="result-top">
        <div><span class="panel-kicker">ANALYSIS ${esc(String(data.status || 'COMPLETED').toUpperCase())}</span>
        <h2>${esc(data.filename || data.indicator || 'Investigation')}</h2>
        <p>${esc(data.indicator_type || 'indicator')} · ${esc(data.mode || '')}</p></div>
        <div class="score-ring ${esc(level)}"><strong>${esc(data.threat_score ?? 0)}</strong><small>/100</small></div>
      </div>
      <div class="severity-banner ${esc(level)}"><b>${esc(data.threat_level || 'UNKNOWN')}</b><span>${esc(data.message || 'Investigation completed.')}</span></div>
      ${modelCard(data)}
      ${data.file ? `<div class="result-section"><h3>File intake</h3><div class="detail-grid">
        <div><small>SHA256</small><b>${esc(data.file.sha256)}</b></div>
        <div><small>MIME</small><b>${esc(data.file.mime_type)}</b></div>
        <div><small>TYPE</small><b>${esc(data.file.magic_type)}</b></div>
        <div><small>SIZE</small><b>${esc(data.file.size)} bytes</b></div>
        <div><small>ENTROPY</small><b>${esc(data.file.entropy)}</b></div>
        <div><small>SANDBOX</small><b>${esc(data.sandbox?.status || 'not requested')}</b></div>
      </div></div>` : ''}
      <div class="result-section"><h3>Source correlation</h3>
        <div class="source-grid">${sourceMarkup || '<div class="empty-state">No provider observations were returned.</div>'}</div>
      </div>
      ${errors}
      <div class="notice info">The rule-based CTI score and the ML classifier are separate signals. A model prediction is not proof that an indicator is safe or malicious.</div>
      ${reportLink}
    </section>`;
    result.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (analyzeButton.disabled) return;

    let requestPromise;
    try {
      analyzeButton.disabled = true;
      analyzeButton.textContent = 'Analyzing…';
      result.innerHTML = `<div class="loading-panel"><div class="loader"></div><b>Correlating intelligence…</b><small>Checking configured providers, running the local URL model and saving the evidence. This may take several seconds.</small></div>`;

      if (mode === 'FILE') {
        const file = fileInput.files && fileInput.files[0];
        if (!file) throw new Error('Select a file first.');
        const formData = new FormData();
        formData.append('file', file);
        formData.append('sandbox', document.getElementById('sandbox-file').checked ? 'true' : 'false');
        requestPromise = CTI.fetchJSON('/api/analyze/file', { method: 'POST', body: formData });
      } else {
        const value = input.value.trim();
        if (!value) throw new Error('Enter an indicator before selecting Analyze.');
        if (mode === 'URL') {
          let parsed;
          try { parsed = new URL(value); } catch { throw new Error('Enter a complete URL, for example https://example.com'); }
          if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Only http:// and https:// URLs are supported.');
        }
        requestPromise = window.analyzeIndicator(value, {
          deep_scan: mode === 'URL' && document.getElementById('deep-vt-scan').checked,
          refresh: mode === 'IP' && document.getElementById('refresh-vt-analysis').checked
        });
      }
      const response = await requestPromise;
      render(response);
      CTI.toast('Investigation completed and report saved.', 'success');
    } catch (error) {
      showError(error && error.message ? error.message : 'Unexpected frontend error.');
      CTI.toast(error.message || 'Investigation failed.', 'error');
    } finally {
      analyzeButton.disabled = false;
      analyzeButton.textContent = mode === 'FILE' ? 'Analyze File →' : 'Analyze →';
    }
  });

  updateOptions();
  const query = new URLSearchParams(location.search);
  if (query.get('indicator')) input.value = query.get('indicator');
})();
