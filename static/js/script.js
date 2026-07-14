const form = document.getElementById('scanForm');
const input = document.getElementById('urlInput');
const btn = document.getElementById('scanBtn');
const resultArea = document.getElementById('resultArea');
const verdictBadge = document.getElementById('verdictBadge');
const riskScore = document.getElementById('riskScore');
const meterFill = document.getElementById('meterFill');
const targetUrl = document.getElementById('targetUrl');
const reasonsList = document.getElementById('reasonsList');
const intelRow = document.getElementById('intelRow');

const VERDICT_COLORS = {
  safe: '#4ade9b',
  suspicious: '#f0a83c',
  dangerous: '#ef5b5b',
};

document.querySelectorAll('.chip').forEach(chip => {
  chip.addEventListener('click', () => {
    input.value = chip.dataset.url;
    form.dispatchEvent(new Event('submit'));
  });
});

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = input.value.trim();
  if (!url) return;

  btn.disabled = true;
  btn.textContent = 'Scanning…';

  try {
    const res = await fetch('/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || 'Something went wrong');
    }

    renderResult(data);
  } catch (err) {
    renderError(err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Scan';
  }
});

function renderResult(data) {
  resultArea.hidden = false;

  const verdict = data.final_verdict;
  verdictBadge.textContent = verdict;
  verdictBadge.className = `verdict-badge ${verdict}`;

  riskScore.textContent = `Risk: ${data.risk_score}/100`;
  targetUrl.textContent = data.url;

  meterFill.style.width = '0%';
  meterFill.style.background = VERDICT_COLORS[verdict];
  requestAnimationFrame(() => {
    meterFill.style.width = `${data.risk_score}%`;
  });

  reasonsList.innerHTML = '';
  data.reasons.forEach(reason => {
    const li = document.createElement('li');
    li.textContent = reason;
    reasonsList.appendChild(li);
  });

  const intel = data.threat_intel;
  if (intel.available) {
    intelRow.innerHTML = intel.flagged
      ? `<span class="intel-icon">⚠</span> Flagged by Google Safe Browsing: ${intel.threat_types.join(', ')}`
      : `<span class="intel-icon">✓</span> No match found in Google Safe Browsing's live database`;
  } else {
    intelRow.innerHTML = `<span class="intel-icon">·</span> Live threat-intel lookup unavailable (${intel.error})`;
  }

  resultArea.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderError(message) {
  resultArea.hidden = false;
  verdictBadge.textContent = 'error';
  verdictBadge.className = 'verdict-badge dangerous';
  riskScore.textContent = '';
  targetUrl.textContent = message;
  reasonsList.innerHTML = '';
  intelRow.innerHTML = '';
}
