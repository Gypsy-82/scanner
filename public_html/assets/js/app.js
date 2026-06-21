// ── Sidebar collapse ──────────────────────────────────────────
(function() {
  const sidebar = document.getElementById('sidebar');
  const btn     = document.getElementById('sidebar-toggle');
  if (!sidebar || !btn) return;

  if (localStorage.getItem('sidebar-collapsed') === '1') {
    sidebar.classList.add('collapsed');
  }

  btn.addEventListener('click', () => {
    const collapsed = sidebar.classList.toggle('collapsed');
    localStorage.setItem('sidebar-collapsed', collapsed ? '1' : '0');
  });
})();

// ── Tab switching ─────────────────────────────────────────────
document.querySelectorAll('.nav-link[data-tab]').forEach(link => {
  link.addEventListener('click', e => {
    e.preventDefault();
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    link.classList.add('active');
    document.getElementById('tab-' + link.dataset.tab).classList.add('active');
  });
});

// ── File drop zone ────────────────────────────────────────────
const dropZone = document.getElementById('file-drop');
const fileInput = document.getElementById('file-input');
const fileName  = document.getElementById('file-name');

if (dropZone && fileInput) {
  // Drag events for visual feedback
  dropZone.addEventListener('dragover',  e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    if (e.dataTransfer.files[0]) {
      // DataTransfer → file input
      const dt = new DataTransfer();
      dt.items.add(e.dataTransfer.files[0]);
      fileInput.files = dt.files;
      showFileName(e.dataTransfer.files[0].name);
    }
  });

  // File selected via the input (overlaid on drop zone — no double-click issue)
  fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) showFileName(fileInput.files[0].name);
  });

  function showFileName(name) {
    fileName.textContent = name;
    dropZone.classList.add('has-file');
  }
}

// ── Generic AJAX form handler ─────────────────────────────────
async function submitScan(formId, endpoint, resultsId, renderFn) {
  const form    = document.getElementById(formId);
  const results = document.getElementById(resultsId);
  const btn     = form.querySelector('.btn-scan');

  form.addEventListener('submit', async e => {
    e.preventDefault();
    btn.disabled = true;
    results.innerHTML = '<div class="spinner">Scanning...</div>';

    try {
      const fd  = new FormData(form);
      const route = window.ROUTES && window.ROUTES[endpoint];
      if (!route) { results.innerHTML = `<div class="alert alert-danger">Session expired — please log in again.</div>`; btn.disabled = false; return; }
      const res = await fetch('/' + route, { method: 'POST', body: fd });
      if (res.status === 401 || res.status === 404) {
        results.innerHTML = `<div class="alert alert-danger">Session expired — <a href="/" style="color:var(--accent)">click here to log in again</a></div>`;
        btn.disabled = false; return;
      }
      const data = await res.json();
      results.innerHTML = '';
      renderFn(results, data);
    } catch (err) {
      results.innerHTML = `<div class="alert alert-danger">Request failed: ${err.message}</div>`;
    } finally {
      btn.disabled = false;
    }
  });
}

// ── Helpers ───────────────────────────────────────────────────
const h = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const badge = sev => `<span class="badge ${h(sev)}">${h(sev)}</span>`;

function verdictBar(verdict, severity, label) {
  const cls = severity === 'low' && verdict === 'clean' ? 'clean' : (severity || 'unknown');
  return `<div class="verdict-bar ${cls}">
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    ${h(label || verdict.toUpperCase())}
  </div>`;
}

function findingsList(findings) {
  if (!findings || !findings.length) return '<p style="padding:12px 16px;color:var(--low);font-size:13px;">No findings — looks clean</p>';
  return '<ul class="findings-list">' +
    findings.map(f =>
      `<li>${badge(f.severity || 'info')} <span>${h(f.detail)}${f.url ? ` <a class="ext-link" href="${h(f.url)}" target="_blank" rel="noopener">↗</a>` : ''}</span></li>`
    ).join('') +
    '</ul>';
}

function kvTable(obj) {
  if (!obj || typeof obj !== 'object') return `<div class="mono-block">${h(JSON.stringify(obj, null, 2))}</div>`;
  return '<table class="kv-table">' +
    Object.entries(obj).map(([k, v]) => {
      const val = (v === null || v === undefined) ? '<span style="color:var(--muted)">null</span>' :
                  typeof v === 'object' ? `<code style="font-family:var(--font-mono);font-size:11px">${h(JSON.stringify(v))}</code>` :
                  h(String(v));
      return `<tr><td>${h(k)}</td><td>${val}</td></tr>`;
    }).join('') +
    '</table>';
}

function section(title, content) {
  return `<div class="section-block"><h3>${h(title)}</h3>${content}</div>`;
}

// ── FILE SCAN renderer ────────────────────────────────────────
submitScan('form-file', 'file', 'results-file', (el, d) => {
  if (d.error) { el.innerHTML = `<div class="alert alert-danger">${h(d.error)}</div>`; return; }

  let html = verdictBar(d.verdict, d.severity, `Verdict: ${d.verdict.toUpperCase()} — ${d.filename}`);

  // File info
  const entropyColor = d.entropy > 7.2 ? 'var(--critical)' : d.entropy > 6.5 ? 'var(--medium)' : 'var(--low)';
  html += section('File Info', kvTable({
    'Filename':        d.filename,
    'Detected Type':   d.file_type || d.mime || '—',
    'Extension':       d.extension ? '.' + d.extension : '—',
    'Size':            d.size ? (d.size / 1024).toFixed(1) + ' KB' : '—',
    'MIME':            d.mime,
    'Entropy':         d.entropy !== undefined
                         ? `<span style="color:${entropyColor}">${d.entropy}/8.0${d.entropy > 7.2 ? ' ⚠ high — possible obfuscation' : ''}</span>`
                         : '—',
    'Header Entropy':  d.header_entropy !== undefined ? `${d.header_entropy}/8.0` : '—',
    'Extension Spoof': d.extension_spoof
                         ? '<span style="color:var(--critical)">YES — magic bytes do not match extension</span>'
                         : '<span style="color:var(--low)">No</span>',
    'SHA-256':         d.sha256,
    'MD5':             d.md5,
  }));

  // Findings
  html += section('Findings', d.findings && d.findings.length
    ? findingsList(d.findings)
    : '<p style="padding:12px 16px;color:var(--low);font-size:13px;">No suspicious patterns detected.</p>');

  // Extracted URLs
  if (d.extracted_urls && d.extracted_urls.length > 0) {
    const urlList = d.extracted_urls.map(u =>
      `<li style="padding:5px 16px;border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:12px;word-break:break-all;color:var(--accent2)">${h(u)}</li>`
    ).join('');
    html += section(`Extracted URLs (${d.extracted_urls.length})`, `<ul style="list-style:none">${urlList}</ul>`);
  }

  // ClamAV
  if (d.clamav) {
    const cv = d.clamav.error ? `<div class="mono-block">${h(d.clamav.error)}</div>` :
      kvTable({'Clean': d.clamav.clean ? 'Yes' : 'NO — MALWARE DETECTED', 'Detections': (d.clamav.detections || []).join(', ') || 'None'});
    html += section('ClamAV', cv);
  }

  // pdfid
  if (d.pdfid) {
    let phtml = '';
    if (d.pdfid.error) {
      phtml = `<div class="mono-block">${h(d.pdfid.error)}</div>`;
    } else {
      // Metadata
      const m = d.pdfid.meta || {};
      const hasMeta = Object.values(m).some(Boolean);
      if (hasMeta || d.pdfid.pages) {
        phtml += kvTable({
          'Pages':    d.pdfid.pages || '—',
          'Title':    m.title    || '—',
          'Author':   m.author   || '—',
          'Creator':  m.creator  || '—',
          'Producer': m.producer || '—',
          'Created':  m.created  || '—',
          'Modified': m.modified || '—',
        });
      }
      phtml += `<div class="mono-block">${h(d.pdfid.raw)}</div>`;
    }
    html += section('PDFiD Analysis', phtml);
  }

  // Strings
  if (d.strings && Object.keys(d.strings.hits || {}).length > 0) {
    const nonEmpty = Object.entries(d.strings.hits).filter(([, v]) => v.length > 0);
    if (nonEmpty.length > 0) {
      let shtml = '';
      for (const [label, matches] of nonEmpty) {
        shtml += `<div style="padding:8px 16px;border-bottom:1px solid var(--border)"><strong style="color:var(--medium)">${h(label)}</strong>`;
        shtml += `<div class="mono-block">${matches.map(m => h(m)).join('\n')}</div></div>`;
      }
      html += section(`Pattern Matches (${nonEmpty.length} type(s))`, shtml);
    }
  }

  // ── Image Analysis ───────────────────────────────────────────
  if (d.image_analysis) {
    const ia = d.image_analysis;

    // Appended data — highest priority, show first and loudest
    if (ia.appended_data) {
      const ap = ia.appended_data;
      const warnHtml = `
        <div style="background:rgba(248,81,73,.12);border:1px solid var(--critical);border-radius:6px;padding:14px 18px;margin:12px 16px 0">
          <div style="color:var(--critical);font-weight:700;font-size:14px;margin-bottom:6px">
            ⚠ ${ap.size.toLocaleString()} bytes of data hidden after image EOF at offset 0x${ap.offset.toString(16).toUpperCase()}
          </div>
          <div style="color:var(--muted);font-size:12px">This data is invisible when the image is displayed but can be read by scripts or server-side code.</div>
        </div>
        <div style="padding:10px 16px 4px;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em">Hex Dump</div>
        <div class="mono-block" style="font-size:11px;line-height:1.6">${h(ap.hex_dump)}</div>
        <div style="padding:10px 16px 4px;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em">Text Preview (printable chars)</div>
        <div class="mono-block" style="font-size:11px;line-height:1.6;color:var(--accent)">${h(ap.text_preview)}</div>`;
      html += section('Appended Data After EOF', warnHtml);
    }

    // Polyglot detection
    if (ia.polyglot_hits && ia.polyglot_hits.length > 0) {
      let ptbl = '<table class="kv-table">';
      ptbl += '<tr><td style="font-weight:600;color:var(--muted)">Type</td><td style="font-weight:600;color:var(--muted)">Offset</td><td style="font-weight:600;color:var(--muted)">Hex bytes</td></tr>';
      for (const p of ia.polyglot_hits) {
        ptbl += `<tr>
          <td><span class="badge critical">${h(p.type)}</span></td>
          <td style="font-family:var(--font-mono)">0x${p.offset.toString(16).toUpperCase()}</td>
          <td style="font-family:var(--font-mono);font-size:11px">${h(p.hex_preview)}</td>
        </tr>`;
      }
      ptbl += '</table>';
      html += section(`Polyglot Detection (${ia.polyglot_hits.length} secondary format${ia.polyglot_hits.length>1?'s':''})`, ptbl);
    }

    // SVG scripts
    if (ia.svg_scripts && ia.svg_scripts.length > 0) {
      let sv = '';
      for (const script of ia.svg_scripts) {
        sv += `<div style="padding:8px 16px;border-bottom:1px solid var(--border)"><div class="mono-block" style="font-size:11px;color:var(--critical)">${h(script)}</div></div>`;
      }
      html += section(`SVG Embedded Scripts (${ia.svg_scripts.length})`, sv);
    }
    if (ia.svg_handlers && ia.svg_handlers.length > 0) {
      let sv = '';
      for (const evt of ia.svg_handlers) {
        sv += `<div style="padding:8px 16px;border-bottom:1px solid var(--border)"><div class="mono-block" style="font-size:11px;color:var(--high)">${h(evt)}</div></div>`;
      }
      html += section(`SVG Event Handlers (${ia.svg_handlers.length})`, sv);
    }

    // EXIF / XMP / IPTC metadata
    const allMeta = [
      ...ia.exif_fields.map(f => ({ source: 'EXIF', ...f })),
      ...ia.xmp_fields .map(f => ({ source: 'XMP',  tag: f.key, value: f.value })),
      ...ia.iptc_fields.map(f => ({ source: 'IPTC', ...f })),
    ];
    if (allMeta.length > 0) {
      const PAYLOAD_RE = /<\?php|<\?=|eval\s*\(|base64_decode|<script|javascript:|powershell|cmd\.exe|\/bin\/sh|shell_exec|passthru|system\s*\(/i;
      let mtbl = '<table class="kv-table">';
      for (const { source, tag, value } of allMeta) {
        const suspicious = PAYLOAD_RE.test(value);
        const valHtml = suspicious
          ? `<span style="color:var(--critical);font-weight:600">${h(value)}</span> <span class="badge critical">payload</span>`
          : h(value);
        mtbl += `<tr>
          <td style="font-family:var(--font-mono);font-size:11px;white-space:nowrap">
            <span style="color:var(--muted);font-size:10px">${h(source)}</span> ${h(tag)}
          </td>
          <td style="font-size:12px;word-break:break-all">${valHtml}</td>
        </tr>`;
      }
      mtbl += '</table>';
      html += section(`Image Metadata (${allMeta.length} field${allMeta.length>1?'s':''})`, mtbl);
    }

    // Embedded comments / text chunks
    if (ia.comments && ia.comments.length > 0) {
      let ctbl = '';
      for (const c of ia.comments) {
        const PAYLOAD_RE = /<\?php|<\?=|eval\s*\(|base64_decode|<script|javascript:|powershell|cmd\.exe|\/bin\/sh|shell_exec|passthru|system\s*\(/i;
        const susp = PAYLOAD_RE.test(c.value);
        ctbl += `<div style="padding:10px 16px;border-bottom:1px solid var(--border)">
          <div style="font-size:11px;color:var(--muted);margin-bottom:4px">${h(c.type)}</div>
          <div class="mono-block" style="font-size:11px;${susp?'color:var(--critical)':''}">${h(c.value)}</div>
        </div>`;
      }
      html += section(`Embedded Text / Comments (${ia.comments.length})`, ctbl);
    }

    // Image info summary
    const imgInfo = {};
    if (ia.thumbnail_present)    imgInfo['Embedded Thumbnail'] = '<span style="color:var(--medium)">Present — thumbnail may differ from main image</span>';
    if (ia.icc_profile_kb > 0)   imgInfo['ICC Color Profile']  = `${ia.icc_profile_kb} KB`;
    if (ia.svg_ext_refs?.length)  imgInfo['External References'] = ia.svg_ext_refs.slice(0,5).join('<br>');
    if (Object.keys(imgInfo).length) html += section('Image Info', kvTable(imgInfo));

    // Steganography
    if (ia.stego) {
      const st = ia.stego;
      let stHtml = '';

      // Tool signatures
      if (st.tool_signatures && st.tool_signatures.length > 0) {
        stHtml += '<div style="background:rgba(248,81,73,.1);border:1px solid var(--critical);border-radius:6px;padding:12px 16px;margin:10px 16px">';
        stHtml += '<div style="color:var(--critical);font-weight:700;margin-bottom:8px">Steganography Tool Signature(s) Detected</div>';
        let sigTbl = '<table class="kv-table">';
        sigTbl += '<tr><td style="font-weight:600;color:var(--muted)">Tool</td><td style="font-weight:600;color:var(--muted)">Confidence</td><td style="font-weight:600;color:var(--muted)">Matched Pattern</td></tr>';
        for (const s of st.tool_signatures) {
          const badgeCls = s.confidence === 'certain' ? 'critical' : s.confidence === 'high' ? 'high' : 'medium';
          sigTbl += `<tr>
            <td style="font-weight:600">${h(s.tool)}</td>
            <td><span class="badge ${badgeCls}">${h(s.confidence)}</span></td>
            <td style="font-family:var(--font-mono);font-size:11px">${h(s.pattern)}</td>
          </tr>`;
        }
        sigTbl += '</table>';
        stHtml += sigTbl + '</div>';
      }

      // PNG LSB analysis
      if (st.lsb) {
        const lsb = st.lsb;
        stHtml += '<div style="padding:10px 16px 0">';

        // Stats row
        const lsbSuspColor = lsb.suspicious ? 'var(--critical)' : 'var(--ok)';
        const lsbSuspLabel = lsb.suspicious ? 'Suspicious (uniform)' : 'Normal';
        stHtml += `<div style="display:flex;gap:20px;flex-wrap:wrap;margin-bottom:10px;font-size:12px">
          <div><span style="color:var(--muted)">Dimensions:</span> ${lsb.width}×${lsb.height} (${lsb.rows_analyzed} rows analyzed)</div>
          <div><span style="color:var(--muted)">LSBs sampled:</span> ${lsb.lsb_count.toLocaleString()}</div>
          <div><span style="color:var(--muted)">1-bit ratio:</span> ${lsb.lsb_ones_ratio}</div>
          <div><span style="color:var(--muted)">Chi²:</span> <span style="color:${lsbSuspColor};font-weight:600">${lsb.chi2}</span></div>
          <div><span style="color:var(--muted)">LSB distribution:</span> <span style="color:${lsbSuspColor};font-weight:600">${lsbSuspLabel}</span></div>
          ${!lsb.no_filter_dominant ? '<div><span class="badge medium">Note: PNG filters active — extraction may reflect filtered values not raw pixels</span></div>' : ''}
        </div>`;

        if (lsb.embedded_magic) {
          stHtml += `<div style="background:rgba(248,81,73,.12);border:1px solid var(--critical);border-radius:5px;padding:10px 14px;margin-bottom:10px">
            <span style="color:var(--critical);font-weight:700">Embedded file detected in LSB stream: ${h(lsb.embedded_magic)} magic bytes</span>
          </div>`;
        }

        if (lsb.readable_text) {
          stHtml += `<div style="background:rgba(248,81,73,.08);border:1px solid var(--critical);border-radius:5px;padding:10px 14px;margin-bottom:10px">
            <div style="font-size:11px;color:var(--muted);margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em">Readable text extracted from pixel LSBs (printable ratio: ${lsb.printable_ratio})</div>
            <div class="mono-block" style="font-size:11px;color:var(--critical)">${h(lsb.readable_text)}</div>
          </div>`;
        } else {
          stHtml += `<div style="padding:4px 0 8px;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em">First 48 extracted LSB bytes</div>
            <div class="mono-block" style="font-size:11px">${h(lsb.extracted_hex)}</div>
            <div style="font-size:11px;color:var(--muted);margin-top:6px">Preview (non-printable → .): <span style="font-family:var(--font-mono)">${h(lsb.extracted_preview)}</span></div>`;
        }

        stHtml += '</div>';
      }

      // JPEG note
      if (st.jpeg_note) {
        stHtml += `<div style="padding:10px 16px;margin:0 0 4px">
          <div style="background:rgba(99,102,241,.08);border:1px solid var(--accent);border-radius:5px;padding:10px 14px;font-size:12px;color:var(--muted)">
            <span style="color:var(--accent);font-weight:600">JPEG pixel-level stego:</span> ${h(st.jpeg_note)}
          </div>
        </div>`;
      }

      if (!st.tool_signatures.length && !st.lsb && !st.jpeg_note) {
        stHtml += `<div style="padding:12px 16px;font-size:12px;color:var(--muted)">No steganography indicators found.</div>`;
      }

      if (stHtml) html += section('Steganography Analysis', stHtml);
    }
  }

  // VirusTotal
  if (d.virustotal) {
    const vt = d.virustotal;
    if (vt.error) {
      html += section('VirusTotal', `<div class="mono-block">${h(vt.error)}</div>`);
    } else if (!vt.found) {
      html += section('VirusTotal', `<p style="padding:12px 16px;color:var(--muted);font-size:13px;">${h(vt.note || vt.message || 'Not found in VirusTotal database.')}</p>`);
    } else {
      html += section('VirusTotal', kvTable({
        'Malicious':  vt.malicious,
        'Suspicious': vt.suspicious,
        'Harmless':   vt.harmless,
        'Undetected': vt.undetected,
        'Link':       vt.link ? `<a class="ext-link" href="${h(vt.link)}" target="_blank">View on VirusTotal ↗</a>` : '—',
      }));
    }
  }

  el.innerHTML = html;
});

// ── URL SCAN renderer ─────────────────────────────────────────
submitScan('form-url', 'url', 'results-url', (el, d) => {
  if (d.error) { el.innerHTML = `<div class="alert alert-danger">${h(d.error)}</div>`; return; }

  let html = verdictBar(d.verdict, d.severity, `Verdict: ${d.verdict.toUpperCase()} — ${d.url}`);
  html += section('Findings', findingsList(d.findings));

  html += section('Target Info', kvTable({
    'URL':         d.url,
    'Domain':      d.domain,
    'Resolved IP': d.resolved_ip || 'Could not resolve',
  }));

  if (d.urlhaus) {
    const st = d.urlhaus.status === 'is_db' ? '<span style="color:var(--critical)">IN MALWARE DATABASE</span>' : '<span style="color:var(--low)">Not found</span>';
    html += section('URLhaus (Abuse.ch)', kvTable({
      'Status':     st,
      'Threat':     d.urlhaus.threat  || '—',
      'Tags':       (d.urlhaus.tags   || []).join(', ') || '—',
      'Reference':  d.urlhaus.link ? `<a class="ext-link" href="${h(d.urlhaus.link)}" target="_blank">↗ URLhaus report</a>` : '—',
    }));
  }

  if (d.virustotal) {
    const vt = d.virustotal;
    if (vt.status === 'submitted') {
      html += section('VirusTotal', `<p style="padding:12px 16px;color:var(--medium);">URL submitted for scanning. Re-run in 60 seconds for results.</p>`);
    } else if (vt.error) {
      html += section('VirusTotal', `<div class="mono-block">${h(vt.error)}</div>`);
    } else {
      html += section('VirusTotal', kvTable({
        'Malicious':  vt.malicious,
        'Suspicious': vt.suspicious,
        'Harmless':   vt.harmless,
        'Undetected': vt.undetected,
        'Link':       vt.link ? `<a class="ext-link" href="${h(vt.link)}" target="_blank">View on VirusTotal ↗</a>` : '—',
      }));
    }
  }

  if (d.gsb) {
    html += section('Google Safe Browsing', kvTable({
      'Status': d.gsb.safe ? '<span style="color:var(--low)">Safe</span>' : `<span style="color:var(--critical)">UNSAFE — ${(d.gsb.matches||[]).map(m=>m.threatType).join(', ')}</span>`,
    }));
  }

  if (d.abuseipdb) {
    const ab = d.abuseipdb;
    html += section('AbuseIPDB', kvTable({
      'IP':              ab.ip,
      'Abuse Score':     ab.abuse_confidence + '%',
      'Total Reports':   ab.total_reports,
      'ISP':             ab.isp,
      'Country':         ab.country,
      'Usage Type':      ab.usage_type,
      'Tor Exit Node':   ab.is_tor ? 'Yes' : 'No',
    }));
  }

  el.innerHTML = html;
});

// ── SITE AUDIT renderer ───────────────────────────────────────
submitScan('form-site', 'site', 'results-site', (el, d) => {
  if (d.error) { el.innerHTML = `<div class="alert alert-danger">${h(d.error)}</div>`; return; }

  const scoreColor = d.score >= 80 ? 'var(--low)' : d.score >= 50 ? 'var(--medium)' : 'var(--critical)';
  let html = `<div class="verdict-bar ${d.score >= 80 ? 'clean' : d.score >= 50 ? 'medium' : 'critical'}">
    <span class="score-ring" style="color:${scoreColor}">${d.score}/100</span>
    Security Score — ${d.findings.length} finding(s)
  </div>`;

  html += section('Findings', findingsList(d.findings));

  // SSL
  if (d.ssl) {
    html += section('SSL Certificate', kvTable({
      'Valid':    d.ssl.valid ? 'Yes' : 'EXPIRED',
      'Days left':d.ssl.days_left,
      'Expires':  d.ssl.expires,
      'Issuer':   d.ssl.issuer,
      'Subject':  d.ssl.subject,
    }));
  }

  // WP endpoints
  const openEndpoints = (d.wordpress || []).filter(w => w.open);
  if (openEndpoints.length) {
    html += section(`Open Endpoints (${openEndpoints.length})`,
      '<ul class="endpoint-list">' +
      openEndpoints.map(w =>
        `<li><span class="http-code code-${w.code}">${w.code}</span>
         <span class="endpoint-url">${h(w.url)}</span>
         ${badge(w.risk)}
         <span style="color:var(--muted);font-size:11px">${h(w.label)}</span>
         ${w.version_disclosed ? `<span style="color:var(--medium)"> WP ${h(w.version_disclosed)}</span>` : ''}
         </li>`
      ).join('') +
      '</ul>'
    );
  }

  // Security headers
  const missingHdrs = (d.headers || []).filter(h2 => !h2.present && h2.name);
  if (missingHdrs.length) {
    html += section('Missing Security Headers', '<ul class="findings-list">' +
      missingHdrs.map(h2 => `<li>${badge(h2.risk)} <span>${h(h2.name)} not set</span></li>`).join('') +
      '</ul>'
    );
  }

  // REST API namespaces
  const restEntry = (d.wordpress || []).find(w => w.path === '/wp-json/' && w.namespaces);
  if (restEntry) {
    html += section('REST API Namespaces', `<div class="mono-block">${h((restEntry.namespaces || []).join('\n'))}</div>`);
  }

  el.innerHTML = html;
});

// ── OSINT renderer ────────────────────────────────────────────
submitScan('form-osint', 'osint', 'results-osint', (el, d) => {
  if (d.error) { el.innerHTML = `<div class="alert alert-danger">${h(d.error)}</div>`; return; }

  let html = section('Findings', findingsList(d.findings.length ? d.findings : []));

  html += section('Target Info', kvTable({
    'Target':      d.target,
    'Type':        d.is_ip ? 'IP Address' : 'Domain',
    'Resolved IP': d.resolved_ip || '—',
  }));

  if (d.reverse_ip) {
    const ri = d.reverse_ip;
    const srcBadge = ri.source ? `<span style="font-size:11px;padding:2px 7px;border-radius:4px;background:var(--accent);color:#fff;font-weight:600;margin-left:8px;vertical-align:middle">${h(ri.source)}</span>` : '';
    if (ri.error && (!ri.domains || ri.domains.length === 0)) {
      html += section('Reverse IP' + srcBadge, `<div class="mono-block">${h(ri.error)}</div>`);
    } else if (!ri.domains || ri.domains.length === 0) {
      html += section('Reverse IP' + srcBadge, `<p style="padding:12px 16px;color:var(--muted);font-size:13px;">No co-hosted domains found for ${h(ri.ip || '—')}</p>`);
    } else {
      html += section(`Reverse IP — ${ri.domains.length} domain(s) on ${h(ri.ip || '—')}` + srcBadge,
        '<ul class="endpoint-list">' +
        ri.domains.map(dom =>
          `<li><span class="endpoint-url"><a class="ext-link" href="https://${h(dom)}" target="_blank" rel="noopener">${h(dom)}</a></span></li>`
        ).join('') +
        '</ul>'
      );
    }
  }

  if (d.subdomains) {
    const subs = d.subdomains;
    if (subs.error) {
      html += section('Subdomains', `<div class="mono-block">${h(subs.error)}</div>`);
    } else {
      const entries = Object.entries(subs.list || {});
      const live    = entries.filter(([,v]) => v.ip && v.ip !== 'NXDOMAIN');
      const dead    = entries.filter(([,v]) => v.ip === 'NXDOMAIN');
      const unres   = entries.filter(([,v]) => !v.ip);
      const srcBadgeColor = { 'HackerTarget': 'var(--accent)', 'crt.sh': 'var(--accent2)', 'OTX': 'var(--medium)', 'DNS-brute': 'var(--high)', 'MX': '#8b5cf6', 'NS': '#6366f1' };
      const renderItem = ([sub, data]) => {
        const ipColor = !data.ip ? 'var(--muted)' : data.ip === 'NXDOMAIN' ? 'var(--muted)' : 'var(--low)';
        const ipLabel = data.ip || '—';
        const srcColor = srcBadgeColor[data.source] || 'var(--muted)';
        return `<div class="sub-item">
          <div class="sub-name">${h(sub)}</div>
          <div class="sub-ip">
            <span style="color:${ipColor}">${h(ipLabel)}</span>
            <span style="color:${srcColor};font-size:10px;margin-left:6px">${h(data.source)}</span>
          </div>
        </div>`;
      };
      let subHtml = '';
      if (live.length) {
        subHtml += `<div style="padding:6px 16px 2px;font-size:11px;color:var(--low);text-transform:uppercase;letter-spacing:.04em">Live (${live.length})</div>`;
        subHtml += '<div class="sub-grid">' + live.map(renderItem).join('') + '</div>';
      }
      if (dead.length) {
        subHtml += `<div style="padding:6px 16px 2px;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;border-top:1px solid var(--border)">NXDOMAIN / Inactive (${dead.length})</div>`;
        subHtml += '<div class="sub-grid">' + dead.map(renderItem).join('') + '</div>';
      }
      if (unres.length) {
        subHtml += `<div style="padding:6px 16px 2px;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;border-top:1px solid var(--border)">Unresolved (${unres.length})</div>`;
        subHtml += '<div class="sub-grid">' + unres.map(renderItem).join('') + '</div>';
      }
      if (!entries.length) subHtml = '<div style="padding:12px 16px;font-size:12px;color:var(--muted)">No subdomains discovered.</div>';
      html += section(`Subdomains — ${subs.count} found via ${h(subs.source)}`, subHtml);
    }
  }

  if (d.dns && d.dns.length) {
    const relevant = d.dns.filter(r => ['A','MX','NS','TXT','CNAME'].includes(r.type));
    html += section('DNS Records',
      '<table class="kv-table">' +
      relevant.map(r =>
        `<tr><td>${h(r.type)}</td><td style="font-family:var(--font-mono);font-size:12px">${h(r.ip||r.target||r.txt||r.host||'—')}</td></tr>`
      ).join('') +
      '</table>'
    );
  }

  // dig +short — full record breakdown
  if (d.dig) {
    const REC_ORDER = ['A','AAAA','MX','NS','TXT','SOA','CAA'];
    const present = REC_ORDER.filter(t => d.dig[t] && d.dig[t].length > 0);
    const absent  = REC_ORDER.filter(t => !d.dig[t] || d.dig[t].length === 0);
    let digHtml = '<table class="kv-table">';
    for (const type of present) {
      for (const val of d.dig[type]) {
        digHtml += `<tr>
          <td style="font-family:var(--font-mono);font-size:12px;color:var(--accent2);width:60px">${h(type)}</td>
          <td style="font-family:var(--font-mono);font-size:12px;word-break:break-all">${h(val)}</td>
        </tr>`;
      }
    }
    if (absent.length) {
      digHtml += `<tr><td colspan="2" style="color:var(--muted);font-size:11px;padding:8px 16px">
        No records: ${absent.map(t => `<span style="font-family:var(--font-mono)">${h(t)}</span>`).join(' · ')}
      </td></tr>`;
    }
    digHtml += '</table>';
    html += section('dig +short', digHtml);
  }

  // whois
  if (d.whois) {
    const w = d.whois;
    const expiryColor = w.days_until_expiry < 30  ? 'var(--critical)'
                      : w.days_until_expiry < 90  ? 'var(--medium)'
                      : 'var(--low)';
    const expiryLabel = w.expires
      ? `${w.expires} <span style="color:${expiryColor};font-size:11px">(${w.days_until_expiry} days)</span>`
      : '—';

    let whoisHtml = '<table class="kv-table">';
    const rows = {
      'Registrar':   w.registrar || '—',
      'Registered':  w.registered || '—',
      'Updated':     w.updated || '—',
      'Expires':     expiryLabel,
      'Nameservers': (w.nameservers || []).join(', ') || '—',
      'DNSSEC':      w.dnssec === 'unsigned'
                       ? '<span style="color:var(--medium)">unsigned</span>'
                       : `<span style="color:var(--low)">${h(w.dnssec)}</span>`,
      'Privacy':     w.privacy
                       ? '<span style="color:var(--low)">Enabled — registrant details hidden</span>'
                       : '<span style="color:var(--medium)">Disabled — registrant details public</span>',
      'Status':      (w.status || []).join(', ') || '—',
    };
    for (const [k, v] of Object.entries(rows)) {
      whoisHtml += `<tr><td>${h(k)}</td><td style="font-family:var(--font-mono);font-size:12px">${v}</td></tr>`;
    }
    whoisHtml += '</table>';

    // Registrant block
    if (!w.privacy && w.registrant) {
      const reg = w.registrant;
      const fields = {
        'Name':    reg.name,
        'Org':     reg.org,
        'Email':   reg.email,
        'Phone':   reg.phone,
        'Street':  reg.street,
        'City':    reg.city,
        'State':   reg.state,
        'ZIP':     reg.zip,
        'Country': reg.country,
      };
      const available = Object.entries(fields).filter(([,v]) => v && v.trim());
      whoisHtml += '<div style="border-top:1px solid var(--border);padding:10px 16px">';
      whoisHtml += '<div style="font-size:11px;color:var(--muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:.04em">Registrant Details</div>';
      if (available.length) {
        whoisHtml += '<table class="kv-table">' +
          available.map(([k,v]) => `<tr><td>${h(k)}</td><td style="font-family:var(--font-mono);font-size:12px">${h(v)}</td></tr>`).join('') +
          '</table>';
      } else {
        whoisHtml += '<div style="font-size:12px;color:var(--muted);padding:4px 0">Registrant entity present but RDAP response contains no contact fields — registrar may restrict disclosure.</div>';
      }
      whoisHtml += '</div>';
    } else if (!w.privacy && !w.registrant) {
      whoisHtml += '<div style="border-top:1px solid var(--border);padding:10px 16px;font-size:12px;color:var(--muted)">No registrant entity returned by RDAP — registrar may not expose contact data via this protocol. Try a traditional WHOIS lookup for full details.</div>';
    }

    html += section('WHOIS', whoisHtml);
  }

  if (d.shodan) {
    html += section('Shodan', kvTable({
      'IP':    d.shodan.ip,
      'Org':   d.shodan.org || '—',
      'OS':    d.shodan.os  || '—',
      'Ports': (d.shodan.ports || []).join(', ') || '—',
      'CVEs':  (d.shodan.vulns || []).join(', ')  || 'None known',
    }));
  }

  el.innerHTML = html;
});

// ── INSPECTOR renderer ───────────────────────────────────────
submitScan('form-inspect', 'inspect', 'results-inspect', (el, d) => {
  if (d.error) { el.innerHTML = `<div class="alert alert-danger">${h(d.error)}</div>`; return; }

  // Overall verdict bar
  const sevLabel = { critical: 'CRITICAL', high: 'HIGH RISK', medium: 'MEDIUM RISK', low: 'LOW RISK', info: 'INFO' };
  let html = verdictBar(d.severity, d.severity, `Inspector: ${sevLabel[d.severity] || d.severity.toUpperCase()} — ${d.findings ? d.findings.length : 0} finding(s) — ${d.domain}`);

  // Consolidated findings
  html += section('All Findings', findingsList(d.findings));

  // Request / response metadata
  html += section('Response Info', kvTable({
    'Final URL':    d.final_url,
    'HTTP Code':    d.http_code,
    'Content-Type': d.content_type,
  }));

  // Raw response headers table
  if (d.headers && Object.keys(d.headers).length) {
    let tbl = '<table class="kv-table">';
    for (const [name, vals] of Object.entries(d.headers)) {
      const valStr = Array.isArray(vals) ? vals.join(', ') : String(vals ?? '');
      tbl += `<tr><td style="font-family:var(--font-mono);font-size:11px">${h(name)}</td><td style="font-family:var(--font-mono);font-size:11px">${h(valStr)}</td></tr>`;
    }
    tbl += '</table>';
    html += section('Response Headers', tbl);
  }

  // Header security issues (present leaks + missing required)
  if (d.header_issues && d.header_issues.length) {
    const issues = d.header_issues.map(i => ({
      severity: i.severity,
      detail:   i.value === null
        ? `MISSING [${i.header}] — ${i.msg.replace('MISSING: ', '')}`
        : `[${i.header}: ${i.value}] — ${i.msg}`,
    }));
    html += section('Header Security Analysis', findingsList(issues));
  }

  // CORS
  if (d.cors) {
    const rows = {
      'Access-Control-Allow-Origin':      d.cors.origin,
      'Access-Control-Allow-Credentials': d.cors.credentials || '—',
      'Access-Control-Allow-Methods':     d.cors.methods     || '—',
      'Access-Control-Allow-Headers':     d.cors.allow_headers || '—',
    };
    let corsHtml = kvTable(rows);
    if (d.cors.issues && d.cors.issues.length) {
      corsHtml += '<ul class="findings-list">' + d.cors.issues.map(i => `<li>${badge('high')} <span>${h(i)}</span></li>`).join('') + '</ul>';
    }
    html += section('CORS Configuration', corsHtml);
  }

  // Cookies
  if (d.cookies && d.cookies.length) {
    let chtml = '<ul class="findings-list">';
    for (const c of d.cookies) {
      const flags = [
        c.httponly ? '<span style="color:var(--low)">HttpOnly</span>'  : '<span style="color:var(--critical)">No HttpOnly</span>',
        c.secure   ? '<span style="color:var(--low)">Secure</span>'    : '<span style="color:var(--critical)">No Secure</span>',
        c.samesite ? `<span style="color:var(--low)">SameSite=${h(c.samesite)}</span>` : '<span style="color:var(--medium)">No SameSite</span>',
      ].join(' · ');
      const sev = c.sensitive && (!c.httponly || !c.secure) ? 'critical' : (c.issues && c.issues.length ? 'medium' : 'info');
      chtml += `<li>${badge(sev)} <span><strong>${h(c.name)}</strong> — ${flags}${c.sensitive ? ' <span style="color:var(--medium)">(session/auth cookie)</span>' : ''}</span></li>`;
    }
    chtml += '</ul>';
    html += section('Cookie Analysis', chtml);
  }

  // Hardcoded credentials / secrets
  if (d.credentials && d.credentials.length) {
    let chtml = '<table class="kv-table">';
    chtml += '<tr><td style="font-weight:600;color:var(--muted)">Type</td><td style="font-weight:600;color:var(--muted)">Value</td><td style="font-weight:600;color:var(--muted)">Source</td></tr>';
    for (const c of d.credentials) {
      const sev = c.severity || 'critical';
      const copyId = 'cp-cred-' + Math.random().toString(36).slice(2,8);
      chtml += `<tr>
        <td style="vertical-align:top;padding-top:10px"><span class="badge ${sev}">${h(c.type)}</span></td>
        <td style="font-family:var(--font-mono);font-size:12px;color:var(--critical);word-break:break-all;vertical-align:top;padding-top:10px">
          <span id="${copyId}">${h(c.value)}</span>
          <button class="hash-copy-btn" style="margin-left:6px;vertical-align:middle" onclick="navigator.clipboard.writeText(document.getElementById('${copyId}').textContent)">copy</button>
        </td>
        <td style="font-size:11px;color:var(--muted);vertical-align:top;padding-top:10px">
          ${h(c.source.split('/').pop())}
          ${c.line ? `<span style="color:var(--accent)">:${c.line}</span>` : ''}
          <div style="color:var(--muted);font-size:10px;word-break:break-all;margin-top:2px">${h(c.source)}</div>
        </td>
      </tr>`;
    }
    chtml += '</table>';
    html += section(`Hardcoded Credentials / Secrets (${d.credentials.length})`, chtml);
  }

  // Hardcoded hash values
  if (d.hardcoded_hashes && d.hardcoded_hashes.length) {
    let hhtml = '<table class="kv-table">';
    hhtml += '<tr><td style="font-weight:600;color:var(--muted)">Hash Type</td><td style="font-weight:600;color:var(--muted)">Value</td><td style="font-weight:600;color:var(--muted)">Source</td></tr>';
    for (const hh of d.hardcoded_hashes) {
      const copyId = 'cp-hash-' + Math.random().toString(36).slice(2,8);
      hhtml += `<tr>
        <td style="vertical-align:top;padding-top:10px"><span class="badge ${hh.severity}">${h(hh.type)}</span></td>
        <td style="font-family:var(--font-mono);font-size:11px;color:var(--high);word-break:break-all;vertical-align:top;padding-top:10px">
          <span id="${copyId}">${h(hh.value)}</span>
          <button class="hash-copy-btn" style="margin-left:6px;vertical-align:middle" onclick="navigator.clipboard.writeText(document.getElementById('${copyId}').textContent)">copy</button>
        </td>
        <td style="font-size:11px;color:var(--muted);vertical-align:top;padding-top:10px">
          ${h(hh.source.split('/').pop())}<span style="color:var(--accent)">:${hh.line}</span>
          <div style="font-family:var(--font-mono);font-size:10px;color:var(--muted);margin-top:3px;word-break:break-all">${h(hh.context)}</div>
        </td>
      </tr>`;
    }
    hhtml += '</table>';
    html += section(`Hardcoded Hashes (${d.hardcoded_hashes.length})`, hhtml);
  }

  // Base64 encoded strings
  if (d.encoded_strings && d.encoded_strings.length) {
    let ehtml = '<table class="kv-table">';
    ehtml += '<tr><td style="font-weight:600;color:var(--muted)">Encoded (raw)</td><td style="font-weight:600;color:var(--muted)">Decoded plaintext</td><td style="font-weight:600;color:var(--muted)">Source</td></tr>';
    for (const es of d.encoded_strings) {
      const credFlag = es.severity === 'critical';
      const rawId  = 'cp-b64r-' + Math.random().toString(36).slice(2,8);
      const decId  = 'cp-b64d-' + Math.random().toString(36).slice(2,8);
      ehtml += `<tr>
        <td style="font-family:var(--font-mono);font-size:10px;color:var(--muted);word-break:break-all;vertical-align:top;padding-top:10px;max-width:180px">
          <span id="${rawId}">${h(es.raw)}</span>
          <button class="hash-copy-btn" style="margin-left:4px" onclick="navigator.clipboard.writeText(document.getElementById('${rawId}').textContent)">copy</button>
        </td>
        <td style="font-family:var(--font-mono);font-size:12px;${credFlag?'color:var(--critical);font-weight:600':'color:var(--accent)'};word-break:break-all;vertical-align:top;padding-top:10px">
          <span id="${decId}">${h(es.decoded)}</span>
          <button class="hash-copy-btn" style="margin-left:6px" onclick="navigator.clipboard.writeText(document.getElementById('${decId}').textContent)">copy</button>
          ${credFlag ? ' <span class="badge critical" style="margin-left:4px">credential</span>' : ''}
        </td>
        <td style="font-size:11px;color:var(--muted);vertical-align:top;padding-top:10px">
          ${h(es.source.split('/').pop())}<span style="color:var(--accent)">:${es.line}</span>
        </td>
      </tr>`;
    }
    ehtml += '</table>';
    html += section(`Base64 Encoded Strings (${d.encoded_strings.length})`, ehtml);
  }

  // API endpoints — Burp-style table with resolved URL, method, source file
  if (d.api_endpoints && d.api_endpoints.length) {
    const bySource = {};
    for (const ep of d.api_endpoints) {
      const src = ep.source || 'HTML';
      if (!bySource[src]) bySource[src] = [];
      bySource[src].push(ep);
    }
    let epHtml = '';
    for (const [src, eps] of Object.entries(bySource)) {
      const srcLabel = src === d.url ? 'HTML (inline)' : src.split('/').pop() || src;
      epHtml += `<div style="padding:6px 16px 2px;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;border-top:1px solid var(--border)">${h(srcLabel)}</div>`;
      epHtml += '<table class="kv-table" style="margin-bottom:0">';
      for (const ep of eps) {
        const isExternal = (() => { try { return new URL(ep.resolved).hostname !== d.domain; } catch { return false; } })();
        const methodBadge = ep.method && ep.method !== '?'
          ? `<span style="display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700;font-family:var(--font-mono);background:var(--accent);color:#fff;margin-right:6px">${h(ep.method)}</span>`
          : '';
        const extTag = isExternal ? '<span class="badge medium" style="font-size:9px">external</span> ' : '';
        epHtml += `<tr>
          <td style="width:56px">${methodBadge}</td>
          <td style="font-family:var(--font-mono);font-size:12px;word-break:break-all">
            ${extTag}<span style="color:var(--accent)">${h(ep.url)}</span>
          </td>
          <td style="font-family:var(--font-mono);font-size:10px;color:var(--low);word-break:break-all;max-width:300px">
            → ${h(ep.resolved)}
          </td>
          ${ep.line ? `<td style="font-size:10px;color:var(--muted);white-space:nowrap">line ${ep.line}</td>` : '<td></td>'}
        </tr>`;
        if (ep.context) {
          epHtml += `<tr><td></td><td colspan="3" style="font-family:var(--font-mono);font-size:10px;color:var(--muted);padding-top:0;padding-bottom:6px;word-break:break-all">${h(ep.context)}</td></tr>`;
        }
      }
      epHtml += '</table>';
    }
    html += section(`API Endpoints (${d.api_endpoints.length})`, epHtml);
  }

  // HTTP methods (OPTIONS/TRACE)
  if (d.http_methods) {
    const m = d.http_methods;
    let mhtml = kvTable({ 'Allow header': m.allow || '(not returned)', 'HTTP code': m.http_code });
    if (m.issues && m.issues.length) {
      mhtml += '<ul class="findings-list">' + m.issues.map(i => `<li>${badge('high')} <span>${h(i)}</span></li>`).join('') + '</ul>';
    } else if (m.allow) {
      mhtml += `<p style="padding:8px 16px;color:var(--low);font-size:13px;">No dangerous methods detected in Allow header</p>`;
    }
    html += section('HTTP Methods (OPTIONS probe)', mhtml);
  }

  // Cache-Control on auth pages
  if (d.cache_issues && d.cache_issues.length) {
    const ci = d.cache_issues[0];
    html += section('Cache-Control Warning', kvTable({
      'Cache-Control': ci.cache_control,
      'Issue': 'Session cookie present — no-store missing, response may be cached by proxy or browser',
    }));
  }

  // Mixed content
  if (d.mixed_content && d.mixed_content.length) {
    let mchtml = '<ul class="findings-list">';
    for (const item of d.mixed_content) {
      const sev = item.active ? 'high' : 'medium';
      const kind = item.active ? 'Active (blocked by modern browsers, still a finding)' : 'Passive (connection leaks to HTTP)';
      mchtml += `<li>${badge(sev)} <span><strong>${h(item.type)}</strong> — ${kind}<br>
        <code style="font-family:var(--font-mono);font-size:11px;color:var(--medium)">${h(item.url)}</code></span></li>`;
    }
    mchtml += '</ul>';
    html += section(`Mixed Content (${d.mixed_content.length})`, mchtml);
  }

  // SRI missing
  if (d.sri_missing && d.sri_missing.length) {
    let shtml = '<ul class="findings-list">';
    for (const item of d.sri_missing) {
      shtml += `<li>${badge('medium')} <span>
        External <strong>${h(item.type)}</strong> from <strong>${h(item.host)}</strong> — no <code>integrity=</code> attribute<br>
        <code style="font-family:var(--font-mono);font-size:11px;color:var(--muted)">${h(item.url)}</code>
      </span></li>`;
    }
    shtml += '</ul>';
    html += section(`Subresource Integrity Missing (${d.sri_missing.length})`, shtml);
  }

  // Insecure form actions
  if (d.insecure_forms && d.insecure_forms.length) {
    let fhtml = '<ul class="findings-list">';
    for (const form of d.insecure_forms) {
      fhtml += `<li>${badge('high')} <span>Form POSTs to <code style="font-family:var(--font-mono);color:var(--critical)">${h(form.action)}</code> — credentials sent in plaintext over HTTP despite HTTPS page</span></li>`;
    }
    fhtml += '</ul>';
    html += section(`Insecure Form Actions (${d.insecure_forms.length})`, fhtml);
  }

  // Autocomplete on password/card fields
  if (d.autocomplete && d.autocomplete.length) {
    let ahtml = '<ul class="findings-list">';
    for (const field of d.autocomplete) {
      ahtml += `<li>${badge('low')} <span>No <code>autocomplete=off</code> on <strong>${h(field.field_type)}</strong> input — browser stores credentials in local profile<br>
        <code style="font-family:var(--font-mono);font-size:11px;color:var(--muted)">${h(field.tag.substring(0, 120))}</code></span></li>`;
    }
    ahtml += '</ul>';
    html += section(`Autocomplete Issues (${d.autocomplete.length})`, ahtml);
  }

  // localStorage / sessionStorage
  if (d.localstorage && d.localstorage.length) {
    let lhtml = '<ul class="findings-list">';
    for (const item of d.localstorage) {
      lhtml += `<li>${badge('medium')} <span>
        Sensitive key <code style="font-family:var(--font-mono);color:var(--critical)">'${h(item.key)}'</code>
        stored in <strong>${h(item.storage)}</strong> — readable by any same-origin JS (XSS pivot)<br>
        <code style="font-family:var(--font-mono);font-size:11px;color:var(--muted)">${h(item.context)}</code><br>
        <span style="color:var(--muted);font-size:11px">${h(item.source)}</span>
      </span></li>`;
    }
    lhtml += '</ul>';
    html += section(`localStorage / sessionStorage Sensitive Data (${d.localstorage.length})`, lhtml);
  }

  // postMessage without origin check
  if (d.postmessage && d.postmessage.length) {
    let phtml = '<ul class="findings-list">';
    for (const item of d.postmessage) {
      const sev   = item.has_origin_check ? 'info' : 'medium';
      const label = item.has_origin_check ? 'Origin check detected' : 'NO origin check — any window can send messages';
      phtml += `<li>${badge(sev)} <span>
        postMessage listener — ${h(label)}<br>
        <code style="font-family:var(--font-mono);font-size:11px;color:var(--muted)">${h(item.source)}</code>
      </span></li>`;
    }
    phtml += '</ul>';
    html += section(`postMessage Handlers (${d.postmessage.length})`, phtml);
  }

  // Backup / temp file links
  if (d.backup_links && d.backup_links.length) {
    html += section(`Backup / Temp File Links (${d.backup_links.length})`,
      '<ul class="findings-list">' +
      d.backup_links.map(b =>
        `<li>${badge('medium')} <span><code style="font-family:var(--font-mono);color:var(--medium)">${h(b.url)}</code> — backup or temp file linked in HTML</span></li>`
      ).join('') +
      '</ul>'
    );
  }

  // Internal hostnames
  if (d.internal_hosts && d.internal_hosts.length) {
    html += section(`Internal Hostnames Exposed (${d.internal_hosts.length})`,
      '<ul class="findings-list">' +
      d.internal_hosts.map(ih =>
        `<li>${badge('medium')} <span><code style="font-family:var(--font-mono);color:var(--critical)">${h(ih.url)}</code> — internal network topology disclosed</span></li>`
      ).join('') +
      '</ul>'
    );
  }

  // Source maps
  if (d.source_maps && d.source_maps.length) {
    let smhtml = '<table class="kv-table">';
    for (const sm of d.source_maps) {
      const status = sm.accessible
        ? `<span style="color:var(--critical)">EXPOSED (${sm.size_kb} KB) — attacker can read unminified source</span>`
        : `<span style="color:var(--low)">Blocked (HTTP ${sm.http_code})</span>`;
      smhtml += `<tr>
        <td style="font-family:var(--font-mono);font-size:11px">${h(sm.js_url.split('/').pop())}</td>
        <td>${status}</td>
        <td style="font-family:var(--font-mono);font-size:10px;color:var(--muted)">${sm.accessible ? `<a class="ext-link" href="${h(sm.map_url)}" target="_blank" rel="noopener">${h(sm.map_url)} ↗</a>` : h(sm.map_url)}</td>
      </tr>`;
    }
    smhtml += '</table>';
    const exposed = d.source_maps.filter(s => s.accessible).length;
    html += section(`Source Maps (${exposed > 0 ? exposed + ' EXPOSED' : 'all blocked'})`, smhtml);
  }

  // Outdated libraries
  if (d.outdated_libs && d.outdated_libs.length) {
    let libhtml = '<ul class="findings-list">';
    for (const lib of d.outdated_libs) {
      libhtml += `<li>${badge(lib.severity)}
        <span>
          <strong>${h(lib.library)}</strong> v${h(lib.version)}
          <span style="color:var(--muted)"> — detected version is below ${h(lib.below)}</span><br>
          <span style="color:var(--medium);font-size:12px">${h(lib.cve)}: ${h(lib.issue)}</span><br>
          <span style="color:var(--muted);font-size:11px">${h(lib.source)}</span>
        </span></li>`;
    }
    libhtml += '</ul>';
    html += section(`Outdated Libraries with Known CVEs (${d.outdated_libs.length})`, libhtml);
  }

  // DOM XSS sinks
  if (d.dom_xss && d.dom_xss.length) {
    let xhtml = '<ul class="findings-list">';
    for (const sink of d.dom_xss) {
      xhtml += `<li>${badge('medium')}
        <span>
          <strong>${h(sink.sink)}</strong> — line ${h(String(sink.line))}<br>
          <code style="font-family:var(--font-mono);font-size:11px;color:var(--medium)">${h(sink.context)}</code><br>
          <span style="color:var(--muted);font-size:11px">${h(sink.source)}</span>
        </span></li>`;
    }
    xhtml += '</ul>';
    html += section(`DOM XSS Sinks (${d.dom_xss.length})`, xhtml);
  }

  // Verbose error / stack trace disclosures
  if (d.error_disclosures && d.error_disclosures.length) {
    let ehtml = '<ul class="findings-list">';
    for (const e of d.error_disclosures) {
      ehtml += `<li>${badge(e.severity)}
        <span>
          <strong>${h(e.type)}</strong><br>
          <code style="font-family:var(--font-mono);font-size:11px;color:var(--critical);word-break:break-all">${h(e.excerpt)}</code>
        </span></li>`;
    }
    ehtml += '</ul>';
    html += section(`Error / Stack Trace Disclosure (${d.error_disclosures.length})`, ehtml);
  }

  // URL parameter / credential leaks
  if (d.url_param_leaks && d.url_param_leaks.length) {
    let uhtml = '<ul class="findings-list">';
    for (const leak of d.url_param_leaks) {
      uhtml += `<li>${badge('high')}
        <span>
          Sensitive param <code style="font-family:var(--font-mono);color:var(--critical)">${h(leak.param)}=${h(leak.value)}</code>
          in URL — logged in browser history, server logs &amp; Referer headers<br>
          <span style="color:var(--muted);font-size:11px">${h(leak.context)}: ${h(leak.url)}</span>
        </span></li>`;
    }
    uhtml += '</ul>';
    html += section(`Credential / Token in URL (${d.url_param_leaks.length})`, uhtml);
  }

  // JS files scanned
  if (d.js_files && d.js_files.length) {
    html += section(`JS Files Scanned (${d.js_files.length})`,
      '<table class="kv-table">' +
      d.js_files.map(f =>
        `<tr>
          <td style="font-family:var(--font-mono);font-size:11px">${h(f.url)}</td>
          <td>${(f.size / 1024).toFixed(1)} KB</td>
          <td>${f.findings_count > 0 ? `<span style="color:var(--critical)">${f.findings_count} finding(s)</span>` : '<span style="color:var(--low)">Clean</span>'}</td>
        </tr>`
      ).join('') +
      '</table>'
    );
  }

  // Internal IPs exposed
  if (d.internal_ips && d.internal_ips.length) {
    html += section(`Internal IPs Exposed (${d.internal_ips.length})`,
      '<ul class="findings-list">' +
      d.internal_ips.map(ip =>
        `<li>${badge('medium')} <span><strong>${h(ip.ip)}</strong> — <span style="color:var(--muted);font-size:11px">${h(ip.source)}</span></span></li>`
      ).join('') +
      '</ul>'
    );
  }

  // Sensitive comments
  if (d.comments && d.comments.length) {
    html += section(`Sensitive Comments (${d.comments.length})`,
      '<ul class="findings-list">' +
      d.comments.map(c =>
        `<li>${badge('medium')} <span><code style="font-family:var(--font-mono);font-size:11px;color:var(--medium)">${h(c.text.substring(0, 200))}</code><br>
        <span style="color:var(--muted);font-size:11px">Source: ${h(c.source)}</span></span></li>`
      ).join('') +
      '</ul>'
    );
  }

  // Email addresses
  if (d.emails && d.emails.length) {
    html += section(`Email Addresses Found (${d.emails.length})`,
      '<ul class="endpoint-list">' +
      d.emails.map(e =>
        `<li><span class="endpoint-url">${h(e.email)}</span><span style="color:var(--muted);font-size:11px;margin-left:8px">${h(e.source)}</span></li>`
      ).join('') +
      '</ul>'
    );
  }

  el.innerHTML = html;
});

// ── CRAWL renderer ────────────────────────────────────────────
submitScan('form-crawl', 'crawl', 'results-crawl', (el, d) => {
  if (d.error) { el.innerHTML = `<div class="alert alert-danger">${h(d.error)}</div>`; return; }

  const stats = d.stats || {};
  let html = section('Stats', kvTable({
    'Total URLs':   stats.total,
    '200 OK':       stats.ok,
    'Redirects':    stats.redirect,
    '403 Forbidden':stats.forbidden,
    '404 Not Found':stats.not_found,
    'Errors':       stats.error,
    'Findings':     d.findings.length,
  }));

  html += section('Findings', findingsList(d.findings));

  const allResults = d.probed?.length ? d.probed : d.crawled;
  const notFound   = (allResults || []).filter(r => r.code !== 404);
  if (notFound.length) {
    html += section(`Accessible Endpoints (${notFound.length})`,
      '<ul class="endpoint-list">' +
      notFound.map(r =>
        `<li>
          <span class="http-code code-${r.code}">${r.code}</span>
          <span class="endpoint-url"><a class="ext-link" href="${h(r.url)}" target="_blank" rel="noopener">${h(r.url)}</a></span>
          ${r.severity ? badge(r.severity) : ''}
        </li>`
      ).join('') +
      '</ul>'
    );
  }

  el.innerHTML = html;
});

// ── TEST LAB — inject signatures into a real file ─────────────
(function () {

  const INJECTIONS = {
    pdf_openaction: {
      label: '/OpenAction + /JS',
      desc:  'Auto-execute JS on PDF open · triggers /AA additional actions',
      expects: 'suspicious', badge: 'medium', types: ['pdf'],
      payload: '\n%% SCANNER-TEST\n/OpenAction << /S /JavaScript /JS (SCANNER-TEST-PAYLOAD) >>\n/AA << >>\n/JavaScript << /JS (SCANNER-TEST) >>\n',
    },
    pdf_launch: {
      label: '/Launch',
      desc:  'Launch external app — highest-risk PDF execution vector',
      expects: 'malicious', badge: 'critical', types: ['pdf'],
      payload: '\n%% SCANNER-TEST\n/Launch << /Win << /F (cmd.exe) /P (/c calc.exe) >> >>\n',
    },
    pdf_jbig2: {
      label: '/JBIG2Decode',
      desc:  'CVE-2023-3420 family exploit compression technique',
      expects: 'suspicious', badge: 'high', types: ['pdf'],
      payload: '\n%% SCANNER-TEST\n/JBIG2Decode /Filter\n',
    },
    ole_vba: {
      label: 'VBA Macro Streams',
      desc:  'OLE2 macro stream names: Macros, VBA, _VBA_PROJECT',
      expects: 'suspicious', badge: 'high', types: ['ole'],
      payload: '\x00Macros\x00VBA\x00_VBA_PROJECT\x00ThisWorkbook\x00Module1\x00',
    },
    ole_autoopen: {
      label: 'AutoOpen Trigger',
      desc:  'Macro fires automatically on document open',
      expects: 'malicious', badge: 'critical', types: ['ole'],
      payload: '\x00AutoOpen\x00AutoExec\x00Document_Open\x00',
    },
    strings_shell: {
      label: 'Shell Commands',
      desc:  'cmd.exe · powershell -encodedcommand · /bin/bash -c',
      expects: 'suspicious', badge: 'critical', types: ['*'],
      payload: '\ncmd.exe /c powershell -encodedcommand SCANNER-TEST\n/bin/bash -c "wget http://localhost/ | sh"\n',
    },
    strings_creds: {
      label: 'Credential Strings',
      desc:  'Hardcoded password= / api_key= / secret= patterns',
      expects: 'suspicious', badge: 'high', types: ['*'],
      payload: '\npassword="SCANNER-TEST-CRED-abc123"\napi_key="SCANNER-TEST-APIKEY-xyz789"\nsecret="SCANNER-TEST-SECRET-val"\ntoken="SCANNER-TEST-TOKEN-abc"\n',
    },
    strings_shellcode: {
      label: 'Hex Shellcode',
      desc:  '\\x41\\x42... byte-sequence pattern (8+ consecutive \\xNN)',
      expects: 'suspicious', badge: 'high', types: ['*'],
      payload: '\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48\\x41\\x42\\x43\\x44',
    },
    strings_registry: {
      label: 'Registry Keys',
      desc:  'HKEY_LOCAL_MACHINE / HKEY_CURRENT_USER path patterns',
      expects: 'suspicious', badge: 'medium', types: ['*'],
      payload: '\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\nHKEY_CURRENT_USER\\Software\\Classes\\test\n',
    },
    strings_syspaths: {
      label: 'System Paths',
      desc:  '%APPDATA% · %TEMP% · C:\\Windows\\System32 · /etc/passwd',
      expects: 'suspicious', badge: 'medium', types: ['*'],
      payload: '\n%APPDATA%\\Microsoft\\test\n%TEMP%\\payload.exe\nC:\\Windows\\System32\\cmd.exe\n/etc/passwd\n/etc/shadow\n',
    },
  };

  const injectDrop = document.getElementById('inject-drop');
  if (!injectDrop) return;
  const injectInput  = document.getElementById('inject-file-input');
  const injectFName  = document.getElementById('inject-file-name');
  const injectOpts   = document.getElementById('inject-options');
  const injectGrid   = document.getElementById('inject-grid');
  const injectSpoofR = document.getElementById('inject-spoof-row');
  const injectSpoofX = document.getElementById('inject-spoof-ext');
  const btnInject    = document.getElementById('btn-inject');
  const injectStatus = document.getElementById('inject-status');

  let baseBuffer = null, baseName = '', baseType = 'binary';

  injectDrop.addEventListener('dragover',  e => { e.preventDefault(); injectDrop.classList.add('drag-over'); });
  injectDrop.addEventListener('dragleave', () => injectDrop.classList.remove('drag-over'));
  injectDrop.addEventListener('drop', e => { e.preventDefault(); injectDrop.classList.remove('drag-over'); if (e.dataTransfer.files[0]) loadBase(e.dataTransfer.files[0]); });
  injectInput.addEventListener('change', () => { if (injectInput.files[0]) loadBase(injectInput.files[0]); });

  function detectType(buf) {
    const hex = Array.from(new Uint8Array(buf.slice(0, 8))).map(x => x.toString(16).padStart(2,'0')).join('');
    if (hex.startsWith('25504446')) return 'pdf';
    if (hex.startsWith('d0cf11e0')) return 'ole';
    if (hex.startsWith('504b0304')) return 'zip';
    if (hex.startsWith('4d5a'))     return 'exe';
    if (hex.startsWith('7f454c46')) return 'elf';
    return 'binary';
  }

  const TYPE_LABELS = { pdf:'PDF Document', ole:'OLE2 (DOC/XLS/PPT)', zip:'ZIP / DOCX / XLSX', exe:'PE Executable', elf:'ELF Executable', binary:'Binary/Unknown' };

  function loadBase(file) {
    baseName = file.name;
    injectFName.textContent = file.name;
    injectDrop.classList.add('has-file');
    const reader = new FileReader();
    reader.onload = e => {
      baseBuffer = e.target.result;
      baseType   = detectType(baseBuffer);
      buildGrid();
      injectOpts.style.display = injectSpoofR.style.display = btnInject.style.display = '';
      injectStatus.innerHTML = '';
    };
    reader.readAsArrayBuffer(file);
  }

  function buildGrid() {
    injectGrid.innerHTML = '';
    for (const [key, inj] of Object.entries(INJECTIONS)) {
      const ok   = inj.types.includes('*') || inj.types.includes(baseType);
      const card = document.createElement('label');
      card.className = 'inject-card' + (ok ? '' : ' inject-card--dim');
      card.innerHTML =
        `<input type="checkbox" class="inject-check" data-key="${h(key)}"${ok ? '' : ' disabled'}>
         <div class="inject-card-body">
           <div class="inject-card-title">${h(inj.label)}</div>
           <div class="inject-card-desc">${h(inj.desc)}</div>
           <div class="inject-card-foot">
             <span class="badge ${inj.badge}">expect: ${h(inj.expects)}</span>
             ${ok ? '' : `<span class="badge" style="opacity:.35">needs&nbsp;${h(inj.types[0])}</span>`}
           </div>
         </div>`;
      injectGrid.appendChild(card);
    }
  }

  btnInject.addEventListener('click', () => {
    if (!baseBuffer) return;
    const selected = [...document.querySelectorAll('.inject-check:checked')].map(c => c.dataset.key);
    const spoofExt = injectSpoofX.value;
    if (!selected.length && !spoofExt) {
      injectStatus.innerHTML = '<div class="alert alert-warn">Select at least one injection payload, a spoof extension, or both.</div>';
      return;
    }

    let append = '';
    for (const key of selected) append += INJECTIONS[key].payload;

    // latin1 encode — byte-safe for all 0x00–0xFF values
    const appendBytes = new Uint8Array(append.length);
    for (let i = 0; i < append.length; i++) appendBytes[i] = append.charCodeAt(i) & 0xFF;

    const orig = new Uint8Array(baseBuffer);
    const merged = new Uint8Array(orig.length + appendBytes.length);
    merged.set(orig);
    merged.set(appendBytes, orig.length);

    let outName = 'TEST_' + baseName;
    if (spoofExt) {
      const dot = baseName.lastIndexOf('.');
      outName = 'TEST_' + (dot > 0 ? baseName.slice(0, dot) : baseName) + spoofExt;
    }

    // Download — all processing is local, nothing leaves the browser
    const blob = new Blob([merged], { type: 'application/octet-stream' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = outName; a.click();
    URL.revokeObjectURL(url);

    const injLabels = selected.map(k => INJECTIONS[k].label);
    const expectedV = selected.some(k => INJECTIONS[k].expects === 'malicious') ? 'malicious'
                    : selected.length ? 'suspicious' : 'clean';
    const vClass = expectedV === 'malicious' ? 'critical' : expectedV === 'suspicious' ? 'medium' : 'clean';

    injectStatus.innerHTML =
      `<div class="section-block" style="margin-top:16px">
        <h3>Injection Complete</h3>
        <table class="kv-table">
          <tr><td>Output file</td><td style="font-family:var(--font-mono)">${h(outName)}</td></tr>
          <tr><td>Base type</td><td>${h(TYPE_LABELS[baseType] || baseType)}</td></tr>
          <tr><td>Injections</td><td>${injLabels.length ? injLabels.map(l => `<span class="badge medium" style="margin-right:4px">${h(l)}</span>`).join('') : '<span style="color:var(--muted)">None</span>'}</td></tr>
          <tr><td>Spoof ext</td><td>${spoofExt || '<span style="color:var(--muted)">—</span>'}</td></tr>
          <tr><td>Expected verdict</td><td><span class="badge ${vClass}">${expectedV}</span></td></tr>
          <tr><td>Next step</td><td>Upload <code style="font-family:var(--font-mono)">${h(outName)}</code> to <a href="#" class="ext-link" id="goto-filescanner">File Scanner ↑</a></td></tr>
        </table>
      </div>`;

    document.getElementById('goto-filescanner')?.addEventListener('click', e => {
      e.preventDefault();
      document.querySelector('.nav-link[data-tab="file"]')?.click();
    });
  });

})();

// ── Hash & Encode module ──────────────────────────────────────
(function() {
  const out   = document.getElementById('hash-output');
  const input = document.getElementById('hash-input');
  if (!out || !input) return;

  // ── Mode switching ──────────────────────────────────────────
  const MODES = ['hash','hmac','encode','decode','identify','crack'];
  const INPUT_LABELS = {
    hash:     'Input text',
    hmac:     'Input text',
    encode:   'Input text',
    decode:   'Encoded string',
    identify: 'Paste hash to identify',
    crack:    'Paste hash to crack',
  };
  let currentMode = 'hash';

  document.querySelectorAll('.hash-mode-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      currentMode = btn.dataset.mode;
      document.querySelectorAll('.hash-mode-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      MODES.forEach(m => document.getElementById('hp-' + m)?.classList.remove('active'));
      document.getElementById('hp-' + currentMode)?.classList.add('active');
      document.getElementById('hash-input-label').textContent = INPUT_LABELS[currentMode] || 'Input';
      input.placeholder = currentMode === 'crack' || currentMode === 'identify'
        ? 'Paste hash here...' : 'Type or paste text here...';
      out.innerHTML = '';
      if (currentMode === 'crack') loadCrackStatus();
    });
  });

  // ── Algorithm / format pill selectors ──────────────────────
  document.querySelectorAll('.hash-alg-strip').forEach(strip => {
    strip.querySelectorAll('.hash-alg-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        strip.querySelectorAll('.hash-alg-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
      });
    });
  });

  function getActive(stripId) {
    const strip = document.getElementById(stripId) || document.querySelector(`#hp-${currentMode} .hash-alg-strip`);
    return strip?.querySelector('.hash-alg-btn.active')?.dataset?.alg
        || strip?.querySelector('.hash-alg-btn.active')?.dataset?.enc || '';
  }

  // ── Output helpers ──────────────────────────────────────────
  function copyBtn(text) {
    const btn = document.createElement('button');
    btn.className = 'hash-copy-btn';
    btn.textContent = 'Copy';
    btn.onclick = () => { navigator.clipboard.writeText(text); btn.textContent = 'Copied!'; setTimeout(() => btn.textContent='Copy', 1500); };
    return btn;
  }

  function hashTable(hashes, filter) {
    const ALG_LABELS = { md5:'MD5', sha1:'SHA-1', sha256:'SHA-256', sha384:'SHA-384', sha512:'SHA-512' };
    let rows = '';
    for (const [alg, val] of Object.entries(hashes)) {
      if (filter && filter !== 'all' && filter !== alg) continue;
      rows += `<tr>
        <td style="font-size:11px;color:var(--muted);white-space:nowrap;padding-right:12px">${ALG_LABELS[alg]||alg}</td>
        <td class="hash-val" style="font-family:var(--font-mono);font-size:12px;word-break:break-all;color:var(--accent)">${h(val)}</td>
        <td style="padding-left:8px"></td>
      </tr>`;
    }
    const wrap = document.createElement('div');
    wrap.className = 'section-block';
    wrap.innerHTML = `<h3>Result</h3><table class="kv-table" style="table-layout:fixed;width:100%">${rows}</table>`;
    // Add copy buttons after rendering
    wrap.querySelectorAll('tr').forEach((tr, i) => {
      const alg = Object.keys(hashes)[i];
      if (!alg) return;
      if (filter && filter !== 'all' && filter !== alg) return;
      const td = tr.querySelector('td:last-child');
      if (td) td.appendChild(copyBtn(Object.values(hashes)[i]));
    });
    return wrap;
  }

  function textOutput(label, value, color) {
    const wrap = document.createElement('div');
    wrap.className = 'section-block';
    wrap.innerHTML = `<h3>${h(label)}</h3>
      <div style="display:flex;align-items:flex-start;gap:10px;padding:12px 16px">
        <div class="mono-block" style="flex:1;font-size:12px;${color?`color:${color}`:''}word-break:break-all">${h(value)}</div>
      </div>`;
    const footer = document.createElement('div');
    footer.style.cssText = 'padding:8px 16px;border-top:1px solid var(--border);display:flex;gap:8px';
    footer.appendChild(copyBtn(value));
    wrap.appendChild(footer);
    return wrap;
  }

  function identifyOutput(candidates) {
    const CONF_COLOR = { certain:'var(--low)', high:'var(--low)', medium:'var(--medium)', low:'var(--muted)', none:'var(--muted)' };
    let rows = candidates.map(c => `<tr>
      <td style="font-family:var(--font-mono);font-size:13px">${h(c.type)}</td>
      <td>${c.bits ? c.bits + ' bits' : '—'}</td>
      <td><span class="badge ${c.confidence === 'certain' || c.confidence === 'high' ? 'low' : c.confidence === 'medium' ? 'medium' : 'info'}">${h(c.confidence)}</span></td>
    </tr>`).join('');
    const wrap = document.createElement('div');
    wrap.className = 'section-block';
    wrap.innerHTML = `<h3>Hash Identification</h3>
      <table class="kv-table">
        <tr><td style="font-weight:600;color:var(--muted)">Type</td><td style="font-weight:600;color:var(--muted)">Size</td><td style="font-weight:600;color:var(--muted)">Confidence</td></tr>
        ${rows}
      </table>`;
    return wrap;
  }

  // ── Server call ─────────────────────────────────────────────
  async function serverCall(payload) {
    const route = window.ROUTES?.hash;
    if (!route) return { error: 'Hash route not available — reload the page' };
    const r = await fetch('/' + route, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return r.json();
  }

  // ── Rainbow table status loader ──────────────────────────────
  async function loadCrackStatus() {
    const el = document.getElementById('crack-rt-status');
    if (!el) return;
    el.innerHTML = '<span style="color:var(--muted);font-size:12px">Checking rainbow table…</span>';
    const s = await serverCall({ action: 'status' });
    if (s.error) { el.innerHTML = ''; return; }
    const rtHtml = s.configured
      ? `<span class="badge low">Configured</span> <span style="font-size:12px;color:var(--muted)">${h(s.path)} &mdash; ${s.size_mb} MB &mdash; format: ${h(s.format)}</span>`
      : `<span class="badge info">Not configured</span> <span style="font-size:12px;color:var(--muted)">Drop a <code>rainbow.txt</code> file in the scanner directory to enable. Supports hash:plain or wordlist formats.</span>`;
    el.innerHTML = `<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:8px 0">
      <span style="font-size:12px;color:var(--muted)">Bundled wordlist: ${s.wordlist_entries} passwords &nbsp;·&nbsp; Rainbow table: </span>${rtHtml}
    </div>`;
  }

  // ── Client-side encode / decode ──────────────────────────────
  function clientEncode(text, fmt) {
    switch(fmt) {
      case 'base64':    return btoa(unescape(encodeURIComponent(text)));
      case 'base64url': return btoa(unescape(encodeURIComponent(text))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
      case 'hex':       return [...new TextEncoder().encode(text)].map(b=>b.toString(16).padStart(2,'0')).join('');
      case 'url':       return encodeURIComponent(text);
      case 'html':      return text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
      case 'binary':    return [...new TextEncoder().encode(text)].map(b=>b.toString(2).padStart(8,'0')).join(' ');
      case 'rot13':     return text.replace(/[a-zA-Z]/g, c => String.fromCharCode(c.charCodeAt(0) + (c.toLowerCase() < 'n' ? 13 : -13)));
      default:          return text;
    }
  }

  function clientDecode(text, fmt) {
    try {
      switch(fmt) {
        case 'base64':    return decodeURIComponent(escape(atob(text)));
        case 'base64url': { const p=text.replace(/-/g,'+').replace(/_/g,'/'); return decodeURIComponent(escape(atob(p+(p.length%4?'='.repeat(4-p.length%4):'')))); }
        case 'hex':       { const bytes=[]; for(let i=0;i<text.replace(/\s/g,'').length;i+=2) bytes.push(parseInt(text.slice(i,i+2),16)); return new TextDecoder().decode(new Uint8Array(bytes)); }
        case 'url':       return decodeURIComponent(text);
        case 'html':      { const t=document.createElement('textarea'); t.innerHTML=text; return t.value; }
        case 'binary':    return text.trim().split(/\s+/).map(b=>String.fromCharCode(parseInt(b,2))).join('');
        case 'rot13':     return text.replace(/[a-zA-Z]/g, c => String.fromCharCode(c.charCodeAt(0) + (c.toLowerCase() < 'n' ? 13 : -13)));
        default:          return text;
      }
    } catch(e) { return 'Decode error: ' + e.message; }
  }

  // ── Button handlers ──────────────────────────────────────────
  document.getElementById('hash-go')?.addEventListener('click', async () => {
    const text = input.value;
    if (!text) { out.innerHTML = '<div class="alert alert-warn">Enter text to hash.</div>'; return; }
    out.innerHTML = '<div class="spinner">Hashing…</div>';
    const alg = document.querySelector('#hp-hash .hash-alg-btn.active')?.dataset?.alg || 'all';
    const r = await serverCall({ action: 'hash', text });
    if (r.error) { out.innerHTML = `<div class="alert alert-danger">${h(r.error)}</div>`; return; }
    out.innerHTML = '';
    out.appendChild(hashTable(r.hashes, alg));
  });

  document.getElementById('hmac-go')?.addEventListener('click', async () => {
    const text = input.value, key = document.getElementById('hmac-key')?.value;
    if (!text) { out.innerHTML = '<div class="alert alert-warn">Enter text.</div>'; return; }
    if (!key)  { out.innerHTML = '<div class="alert alert-warn">Enter a secret key.</div>'; return; }
    out.innerHTML = '<div class="spinner">Computing HMAC…</div>';
    const alg = document.querySelector('#hp-hmac .hash-alg-btn.active')?.dataset?.alg || 'sha256';
    const r = await serverCall({ action: 'hmac', text, key, algorithm: alg });
    if (r.error) { out.innerHTML = `<div class="alert alert-danger">${h(r.error)}</div>`; return; }
    out.innerHTML = '';
    out.appendChild(textOutput(r.algorithm, r.hash, 'var(--accent)'));
    const info = document.createElement('div');
    info.className = 'section-block';
    info.innerHTML = `<h3>Details</h3>${kvTable({ 'Algorithm': r.algorithm, 'Key': r.key, 'Input': r.input })}`;
    out.appendChild(info);
  });

  document.getElementById('encode-go')?.addEventListener('click', () => {
    const text = input.value;
    if (!text) { out.innerHTML = '<div class="alert alert-warn">Enter text to encode.</div>'; return; }
    const fmt = document.querySelector('#hp-encode .hash-alg-btn.active')?.dataset?.enc || 'base64';
    const result = clientEncode(text, fmt);
    out.innerHTML = '';
    out.appendChild(textOutput(`${fmt.toUpperCase()} Encoded`, result, 'var(--accent)'));
  });

  document.getElementById('decode-go')?.addEventListener('click', () => {
    const text = input.value.trim();
    if (!text) { out.innerHTML = '<div class="alert alert-warn">Enter encoded string to decode.</div>'; return; }
    const fmt = document.querySelector('#hp-decode .hash-alg-btn.active')?.dataset?.enc || 'base64';
    const result = clientDecode(text, fmt);
    out.innerHTML = '';
    out.appendChild(textOutput(`${fmt.toUpperCase()} Decoded`, result, 'var(--accent2)'));
  });

  document.getElementById('identify-go')?.addEventListener('click', async () => {
    const inputHash = input.value.trim();
    if (!inputHash) { out.innerHTML = '<div class="alert alert-warn">Paste a hash to identify.</div>'; return; }
    out.innerHTML = '<div class="spinner">Identifying…</div>';
    const r = await serverCall({ action: 'identify', inputHash });
    if (r.error) { out.innerHTML = `<div class="alert alert-danger">${h(r.error)}</div>`; return; }
    out.innerHTML = '';
    out.appendChild(identifyOutput(r.candidates));
    const lenInfo = document.createElement('div');
    lenInfo.className = 'section-block';
    lenInfo.innerHTML = `<h3>Input Details</h3>${kvTable({ 'Length (chars)': inputHash.length, 'Length (bytes)': Math.round(inputHash.replace(/\s/g,'').length/2), 'Character set': /^[a-f0-9]+$/i.test(inputHash) ? 'Hex (0-9, a-f)' : /^[a-zA-Z0-9+\/=]+$/.test(inputHash) ? 'Base64' : 'Mixed/Other' })}`;
    out.appendChild(lenInfo);
  });

  document.getElementById('crack-go')?.addEventListener('click', async () => {
    const inputHash = input.value.trim();
    if (!inputHash) { out.innerHTML = '<div class="alert alert-warn">Paste a hash to crack.</div>'; return; }
    out.innerHTML = '<div class="spinner">Cracking — checking wordlist and rainbow table…</div>';
    const alg = document.querySelector('#hp-crack .hash-alg-btn.active')?.dataset?.alg || 'auto';
    const r = await serverCall({ action: 'crack', inputHash, algorithm: alg });
    if (r.error) { out.innerHTML = `<div class="alert alert-danger">${h(r.error)}</div>`; return; }
    out.innerHTML = '';

    if (r.cracked) {
      const res = document.createElement('div');
      res.className = 'section-block';
      res.innerHTML = `<h3>Cracked</h3>
        <div style="background:rgba(63,185,80,.1);border:1px solid var(--low);border-radius:6px;padding:16px 20px;margin:12px 16px">
          <div style="font-size:11px;color:var(--muted);margin-bottom:4px">Plaintext</div>
          <div style="font-family:var(--font-mono);font-size:20px;font-weight:700;color:var(--accent)">${h(r.plaintext)}</div>
        </div>
        ${kvTable({ 'Algorithm': r.algorithm?.toUpperCase() || '—', 'Method': r.method?.replace(/_/g,' ') || '—', 'Lines searched': r.lines_searched?.toLocaleString() || '—' })}`;
      out.appendChild(res);
    } else {
      const res = document.createElement('div');
      res.className = 'section-block';
      const rtStatus = r.tried?.rainbow_table
        ? `<span class="badge low">Tried</span>`
        : `<span class="badge info">Not configured</span>`;
      res.innerHTML = `<h3>Not Cracked</h3>
        <div style="background:rgba(88,166,255,.08);border:1px solid var(--border);border-radius:6px;padding:14px 18px;margin:12px 16px;color:var(--muted);font-size:13px">${h(r.note || 'Hash not found.')}</div>
        ${kvTable({
          'Bundled wordlist': `<span class="badge low">Tried</span> <span style="font-size:12px;color:var(--muted)">${(r.tried?.wordlist_size||0).toLocaleString()} passwords</span>`,
          'Rainbow table':    rtStatus,
        })}`;
      if (!r.tried?.rainbow_table) {
        res.innerHTML += `<div style="padding:10px 16px 14px;font-size:12px;color:var(--muted)">
          To enable rainbow table cracking, drop a <code style="font-family:var(--font-mono);color:var(--accent2)">rainbow.txt</code> file into the <code style="font-family:var(--font-mono);color:var(--accent2)">scanner/</code> directory.<br>
          Supported formats: <strong>hash:plaintext</strong> pairs (pre-computed) or one password per line (wordlist).<br>
          Compatible with CrackStation, SecLists, rockyou.txt, and custom tables.
        </div>`;
      }
      out.appendChild(res);
    }

    // Show identify results alongside crack results
    if (r.candidates?.length) {
      out.appendChild(identifyOutput(r.candidates));
    }
  });

  // Load rainbow table status when crack tab first shown
  document.querySelector('.hash-mode-btn[data-mode="crack"]')?.addEventListener('click', loadCrackStatus);
  // Also load on initial crack panel state
  if (currentMode === 'crack') loadCrackStatus();

})();
