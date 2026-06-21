// ── Local dev server for Security Scanner UI testing ──────────
// Serves public_html, handles login mock, mocks all 5 API endpoints
// Usage: node dev-server.js
// Then open: http://localhost:3000

const http  = require('http');
const fs    = require('fs');
const path  = require('path');
const qs    = require('querystring');
const zlib  = require('zlib');

const PORT    = 3000;
const WEBROOT = path.join(__dirname, 'public_html');
const DEV_PASSWORD = 'scanner123'; // test password for local dev

// ── Rainbow table configuration ───────────────────────────────
// Drop your table file at this path (or set RAINBOW_TABLE env var) to enable.
// Two formats are supported — auto-detected from file content:
//   Pre-computed:  hash:plaintext   (one pair per line, fastest)
//   Wordlist:      plaintext        (one word per line, server hashes each)
// Large files are streamed line-by-line — no full load into memory.
const RAINBOW_TABLE_PATH = process.env.RAINBOW_TABLE || path.join(__dirname, 'rainbow.txt');

// ── MIME types ────────────────────────────────────────────────
const MIME = {
  '.html': 'text/html', '.php':  'text/html',
  '.css':  'text/css',  '.js':   'application/javascript',
  '.png':  'image/png', '.jpg':  'image/jpeg',
  '.svg':  'image/svg+xml', '.ico': 'image/x-icon',
};

// ── Route key → mock name mapping ────────────────────────────
const ROUTE_TO_MOCK = {
  file:    'scan_file.php',
  url:     'scan_url.php',
  site:    'scan_site.php',
  osint:   'osint.php',
  crawl:   'crawl.php',
  inspect: 'inspect.php',
  hash:    'hash.php',
};

// ── Per-session token generation (mirrors PHP make_routes()) ──
function makeRoutes() {
  const tok = () => [...Array(16)].map(() => Math.floor(Math.random()*16).toString(16)).join('');
  return { file: tok(), url: tok(), site: tok(), osint: tok(), crawl: tok(), inspect: tok(), hash: tok() };
}

// ── In-memory session store ───────────────────────────────────
const sessions = {};
function makeSession() {
  const id    = Math.random().toString(36).slice(2) + Date.now().toString(36);
  const routes = makeRoutes();
  sessions[id] = { authenticated: true, csrf: 'devcsrf' + Date.now(), routes, ts: Date.now() };
  return { id, routes };
}
function getSession(req) {
  const cookies = Object.fromEntries(
    (req.headers.cookie || '').split(';').map(c => c.trim().split('=').map(decodeURIComponent))
  );
  return sessions[cookies['_s']] || sessions[cookies['scanner_sess']];
}

// ── Parse POST body — handles multipart (binary-safe) + url-encoded ──
function parseBody(req) {
  return new Promise(resolve => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      const raw   = Buffer.concat(chunks);
      const ctype = req.headers['content-type'] || '';

      if (ctype.includes('multipart/form-data')) {
        const bm = ctype.match(/boundary=([^\s;]+)/);
        if (!bm) return resolve({});
        resolve(parseMultipart(raw, bm[1]));
        return;
      }

      const str = raw.toString();
      try { resolve(JSON.parse(str)); } catch {
        resolve(Object.fromEntries(new URLSearchParams(str)));
      }
    });
  });
}

// Binary-safe multipart parser — preserves file content as Buffer
function parseMultipart(raw, boundary) {
  const result  = {};
  const SEP     = Buffer.from('\r\n--' + boundary);
  const FIRST   = Buffer.from('--' + boundary + '\r\n');
  const HDR_END = Buffer.from('\r\n\r\n');

  let start = raw.indexOf(FIRST);
  if (start === -1) return result;
  start += FIRST.length;

  while (start < raw.length) {
    const next    = raw.indexOf(SEP, start);
    const partEnd = next === -1 ? raw.length : next;
    const part    = raw.slice(start, partEnd);

    const hEnd = part.indexOf(HDR_END);
    if (hEnd === -1) break;

    const headers = part.slice(0, hEnd).toString();
    const body    = part.slice(hEnd + 4);

    // Two separate searches — a single greedy regex backtracks onto
    // the 'name=' inside 'filename=' and captures the wrong value
    const nameM     = headers.match(/;\s*name="([^"]+)"/i);
    const filenameM = headers.match(/;\s*filename="([^"]*)"/i);
    if (nameM) {
      const name     = nameM[1];
      const filename = filenameM ? filenameM[1] : undefined;
      if (filename !== undefined) {
        result[name] = { filename, buffer: body, size: body.length };
      } else {
        result[name] = body.toString();
      }
    }

    if (next === -1) break;
    start = next + SEP.length;
    if (raw.slice(start, start + 2).toString() === '--') break;
    start += 2; // skip \r\n after boundary
  }

  return result;
}

// ── Shared HTTP/HTTPS fetch helper ───────────────────────────
const _https = require('https');
const _http  = require('http');

function httpGet(url, { timeout = 10000, method = 'GET', body = null, extraHeaders = {}, maxRedirects = 5, rejectUnauthorized = false } = {}) {
  return new Promise((resolve, reject) => {
    let parsed;
    try { parsed = new URL(url); } catch (e) { return reject(e); }
    const lib = parsed.protocol === 'https:' ? _https : _http;
    const opts = {
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:     parsed.pathname + parsed.search,
      method,
      timeout,
      rejectUnauthorized,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
        'Accept':     'text/html,application/xhtml+xml,application/json,*/*;q=0.9',
        ...extraHeaders,
      },
    };
    const req = lib.request(opts, res => {
      if ([301,302,303,307,308].includes(res.statusCode) && res.headers.location && maxRedirects > 0) {
        res.resume();
        const next = new URL(res.headers.location, url).href;
        return httpGet(next, { timeout, method: 'GET', maxRedirects: maxRedirects - 1, rejectUnauthorized })
          .then(r => resolve({ ...r, finalUrl: r.finalUrl || next })).catch(reject);
      }
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({
        status:   res.statusCode,
        headers:  res.headers,
        body:     Buffer.concat(chunks).toString('utf8'),
        finalUrl: url,
      }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
    if (body) req.write(body);
    req.end();
  });
}

// ── Image analysis helpers ────────────────────────────────────

function hexDump(buf, maxBytes = 192) {
  const bytes = buf.slice(0, maxBytes);
  const lines = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const row  = bytes.slice(i, i + 16);
    const hex  = [...row].map(b => b.toString(16).padStart(2,'0')).join(' ').padEnd(47);
    const text = [...row].map(b => (b >= 0x20 && b < 0x7F) ? String.fromCharCode(b) : '.').join('');
    lines.push(`${i.toString(16).padStart(4,'0')}: ${hex}  ${text}`);
  }
  if (buf.length > maxBytes) lines.push(`         ... (${buf.length - maxBytes} more bytes)`);
  return lines.join('\n');
}

function parseTiffIfd(buf) {
  const fields = [];
  if (buf.length < 8) return fields;
  const byteOrder = buf.slice(0, 2).toString('ascii');
  const le = byteOrder === 'II';
  const u16 = o => { try { return le ? buf.readUInt16LE(o) : buf.readUInt16BE(o); } catch { return 0; } };
  const u32 = o => { try { return le ? buf.readUInt32LE(o) : buf.readUInt32BE(o); } catch { return 0; } };
  if (u16(2) !== 42) return fields;

  const TAGS = {
    0x010E:'ImageDescription', 0x010F:'Make', 0x0110:'Model', 0x0112:'Orientation',
    0x0131:'Software',  0x013B:'Artist',  0x013C:'HostComputer', 0x8298:'Copyright',
    0x9286:'UserComment', 0x0132:'DateTime', 0x9003:'DateTimeOriginal',
    0x9004:'DateTimeDigitized', 0xA004:'RelatedSoundFile',
    0x9C9B:'XPComment', 0x9C9C:'XPAuthor', 0x9C9D:'XPKeywords',
    0x9C9E:'XPSubject', 0x9C9F:'XPTitle',
    0x8769:'ExifIFDPointer', 0x8825:'GPSInfoIFDPointer',
    0x0201:'JPEGInterchangeFormat',
  };
  const SZ = [0,1,1,2,4,8,1,1,2,4,8,4,8];

  const readIfd = (off, depth = 0) => {
    if (depth > 3 || off < 0 || off + 2 > buf.length) return;
    const count = u16(off);
    if (!count || count > 200) return;
    for (let i = 0; i < count; i++) {
      const e    = off + 2 + i * 12;
      if (e + 12 > buf.length) break;
      const tag  = u16(e), type = u16(e+2), cnt = u32(e+4);
      if (!cnt || cnt > 65536) continue;
      if (tag === 0x8769 || tag === 0x8825) { readIfd(u32(e+8), depth+1); continue; }
      const tname = TAGS[tag];
      if (!tname) continue;
      const dsz = (SZ[type]||1) * cnt;
      let vo = e + 8;
      if (dsz > 4) { vo = u32(e+8); if (vo + dsz > buf.length) continue; }
      let value;
      if (type === 2) {
        value = buf.slice(vo, vo+cnt).toString('latin1').replace(/\x00/g,'').trim();
      } else if (type === 7) {
        if (tag === 0x9286 && cnt > 8) {
          const enc  = buf.slice(vo, vo+8).toString('ascii');
          const rest = buf.slice(vo+8, vo+cnt);
          value = enc.startsWith('UNICODE') ? rest.toString('ucs2').replace(/\x00/g,'').trim()
                                            : rest.toString('latin1').replace(/\x00/g,'').trim();
        } else {
          value = buf.slice(vo, vo+Math.min(cnt,256)).toString('latin1').replace(/[^\x20-\x7E]/g,'?').trim();
        }
      } else if (type === 3) { value = String(u16(vo)); }
        else if (type === 4) { value = String(u32(vo)); }
        else { continue; }
      if (value && value.length > 0) fields.push({ tag: tname, value });
    }
  };

  readIfd(u32(4));
  return fields;
}

function parseXmpKeyValues(xmpText) {
  const pairs = [], seen = new Set();
  const re = /((?:dc|xmp|photoshop|Iptc4xmpCore|exif|tiff):[A-Za-z]+)\s*=\s*"([^"]{1,400})"/g;
  let m;
  while ((m = re.exec(xmpText)) !== null) {
    if (!seen.has(m[1])) { pairs.push({ key: m[1], value: m[2] }); seen.add(m[1]); }
  }
  const re2 = /<((?:dc|xmp|photoshop|Iptc4xmpCore|exif|tiff):[A-Za-z]+)>\s*([^<]{1,400})\s*<\/\1>/g;
  while ((m = re2.exec(xmpText)) !== null) {
    if (!seen.has(m[1])) { pairs.push({ key: m[1], value: m[2].trim() }); seen.add(m[1]); }
  }
  return pairs.slice(0, 60);
}

function parseIptc(segData) {
  const fields = [];
  const TAGS = {
    5:'ObjectName', 25:'Keywords', 40:'SpecialInstructions', 55:'DateCreated',
    60:'TimeCreated', 65:'OriginatingProgram', 80:'Byline', 85:'BylineTitle',
    90:'City', 92:'Sublocation', 95:'ProvinceState', 100:'CountryCode',
    101:'Country', 105:'Headline', 110:'Credit', 115:'Source',
    116:'CopyrightNotice', 120:'Caption', 122:'CaptionWriter',
  };
  let pos = 0;
  // Locate IPTC IIM block (may follow Photoshop 8BIM headers)
  const bimIdx = segData.indexOf(Buffer.from([0x38,0x42,0x49,0x4D])); // '8BIM'
  if (bimIdx !== -1) {
    let bp = bimIdx;
    while (bp + 12 <= segData.length) {
      if (segData.slice(bp, bp+4).toString('ascii') !== '8BIM') break;
      const rType = segData.readUInt16BE(bp+4);
      const rLen  = segData.readUInt32BE(bp+8);
      if (rType === 0x0404) { pos = bp + 12; break; }
      bp += 12 + rLen + (rLen % 2);
    }
  }
  while (pos + 5 <= segData.length) {
    if (segData[pos] !== 0x1C) { pos++; continue; }
    const record = segData[pos+1], dataset = segData[pos+2];
    const len = segData.readUInt16BE(pos+3);
    if (pos + 5 + len > segData.length) break;
    const value = segData.slice(pos+5, pos+5+len).toString('utf8').trim();
    pos += 5 + len;
    if (record === 2 && TAGS[dataset] && value) fields.push({ tag: TAGS[dataset], value });
  }
  return fields;
}

function extractPngLsb(buf) {
  // Parse IHDR
  let width = 0, height = 0, colorType = 2;
  let pos = 8;
  while (pos + 12 <= buf.length) {
    const chunkLen  = buf.readUInt32BE(pos);
    const chunkType = buf.slice(pos+4, pos+8).toString('ascii');
    const chunkData = buf.slice(pos+8, pos+8+chunkLen);
    if (chunkType === 'IHDR') {
      width = chunkData.readUInt32BE(0); height = chunkData.readUInt32BE(4); colorType = chunkData[9];
    }
    pos += 4 + 4 + chunkLen + 4;
    if (chunkType === 'IEND') break;
  }
  if (!width || !height) return null;
  // channels: gray=1, RGB=3, palette=1, gray+A=2, RGBA=4
  const channels = [1,0,3,1,2,0,4][colorType] || 3;

  // Collect all IDAT raw bytes
  let idatBufs = [];
  pos = 8;
  while (pos + 12 <= buf.length) {
    const chunkLen  = buf.readUInt32BE(pos);
    const chunkType = buf.slice(pos+4, pos+8).toString('ascii');
    if (chunkType === 'IDAT') idatBufs.push(buf.slice(pos+8, pos+8+chunkLen));
    pos += 4 + 4 + chunkLen + 4;
    if (chunkType === 'IEND') break;
  }
  if (!idatBufs.length) return null;

  let raw;
  try { raw = zlib.inflateSync(Buffer.concat(idatBufs)); } catch { return null; }

  // Each row: 1 filter byte + width*channels pixel bytes
  const rowStride = 1 + width * channels;
  if (raw.length < rowStride) return null;
  const rowsAvail = Math.min(height, Math.floor(raw.length / rowStride));

  // Extract LSBs from pixel bytes (skip filter byte per row), cap at 65536 bits
  const lsbs = [];
  let filterTypes = { 0:0, 1:0, 2:0, 3:0, 4:0 };
  const maxRows = Math.min(rowsAvail, Math.ceil(65536 / (width * channels)));
  for (let r = 0; r < maxRows; r++) {
    const base = r * rowStride;
    const ft = raw[base] & 0x0F;
    filterTypes[ft] = (filterTypes[ft] || 0) + 1;
    for (let c = 1; c <= width * channels && lsbs.length < 65536; c++) {
      lsbs.push(raw[base + c] & 1);
    }
  }

  // Convert LSBs to bytes
  const extractedBytes = [];
  for (let i = 0; i + 7 < lsbs.length; i += 8) {
    let byte = 0;
    for (let b = 0; b < 8; b++) byte = (byte << 1) | lsbs[i+b];
    extractedBytes.push(byte);
  }
  const extracted = Buffer.from(extractedBytes);

  // Chi-square: how close are 0s/1s to 50/50?
  const ones  = lsbs.reduce((a, b) => a + b, 0);
  const zeros = lsbs.length - ones;
  const exp   = lsbs.length / 2;
  const chi2  = (Math.pow(ones - exp, 2) + Math.pow(zeros - exp, 2)) / exp;

  // Readable text check: find any run of 8+ consecutive printable ASCII bytes
  // in the first 512 extracted bytes. Stego tools typically embed null-terminated
  // strings so we also check up to the first null byte.
  const sample512 = extracted.slice(0, 512);
  const nullIdx = sample512.indexOf(0);
  const preMsgLen = nullIdx > 0 ? nullIdx : sample512.length;
  const preMsg = sample512.slice(0, preMsgLen);
  const prePrintable = preMsg.filter(b => b >= 0x20 && b < 0x7F).length;
  const prePrintableRatio = preMsgLen > 0 ? prePrintable / preMsgLen : 0;
  // Either: ratio before null is high, OR long run of printable chars anywhere
  let longestRun = 0, curRun = 0;
  for (const b of sample512) { if (b >= 0x20 && b < 0x7F) { curRun++; longestRun = Math.max(longestRun, curRun); } else curRun = 0; }
  const readableText = (prePrintableRatio > 0.75 && preMsgLen >= 4) || longestRun >= 8
    ? preMsg.length >= 4
      ? preMsg.toString('latin1').replace(/[^\x20-\x7E\n\r]/g, '.').slice(0, 200)
      : sample512.slice(0, 128).toString('latin1').replace(/[^\x20-\x7E\n\r]/g, '.').slice(0, 200)
    : null;
  const printableRatio = prePrintableRatio;

  // Magic number check in first 4 extracted bytes (some tools prepend a header)
  const magic = extracted.slice(0, 4).toString('hex');
  const knownMagics = { '504b0304':'ZIP/SteganoG', '25504446':'PDF', 'ffd8ffe0':'JPEG', '89504e47':'PNG', '52617221':'RAR' };
  const embeddedType = knownMagics[magic] || null;

  const noFilterDominant = (filterTypes[0] / maxRows) > 0.9;

  return {
    width, height, channels, rows_analyzed: maxRows,
    lsb_count: lsbs.length,
    lsb_ones_ratio: Math.round(ones / lsbs.length * 1000) / 1000,
    chi2: Math.round(chi2 * 1000) / 1000,
    // chi2 < 0.1 → very uniform (suspicious); > 4 → clearly non-uniform (natural)
    suspicious: chi2 < 0.5,
    no_filter_dominant: noFilterDominant,
    extracted_hex: extracted.slice(0, 48).toString('hex'),
    extracted_preview: extracted.slice(0, 64).toString('latin1').replace(/[^\x20-\x7E]/g, '.'),
    printable_ratio: Math.round(printableRatio * 100) / 100,
    readable_text: readableText,
    embedded_magic: embeddedType,
  };
}

function analyzeImage(buf, fileType) {
  const findings = [];
  const result = {
    format: fileType, comments: [], exif_fields: [], xmp_fields: [], iptc_fields: [],
    appended_data: null, polyglot_hits: [], svg_scripts: [], svg_handlers: [],
    svg_ext_refs: [], thumbnail_present: false, icc_profile_kb: 0, stego: null, findings,
  };

  const PAYLOAD = [
    { re: /<\?php/i,                      label: 'PHP open tag',        severity: 'critical' },
    { re: /<\?=/,                          label: 'PHP short echo tag',  severity: 'critical' },
    { re: /\bsystem\s*\(/i,               label: 'system() call',       severity: 'critical' },
    { re: /\bexec\s*\(/i,                 label: 'exec() call',         severity: 'critical' },
    { re: /\bpassthru\s*\(/i,             label: 'passthru() call',     severity: 'critical' },
    { re: /\bshell_exec\s*\(/i,           label: 'shell_exec() call',   severity: 'critical' },
    { re: /\beval\s*\(/i,                 label: 'eval() call',         severity: 'critical' },
    { re: /base64_decode\s*\(/i,          label: 'base64_decode()',     severity: 'high'     },
    { re: /<script[\s>]/i,                label: '<script> tag',        severity: 'high'     },
    { re: /javascript:/i,                 label: 'javascript: URI',     severity: 'high'     },
    { re: /powershell/i,                  label: 'PowerShell reference', severity: 'critical' },
    { re: /cmd\.exe/i,                    label: 'cmd.exe reference',   severity: 'critical' },
    { re: /\/bin\/sh|\/bin\/bash/i,       label: 'shell path',          severity: 'critical' },
    { re: /wget\s+http|curl\s+http/i,     label: 'download command',    severity: 'critical' },
    { re: /(password|passwd)\s*[:=]\s*\S{4,}/i, label: 'hardcoded credential', severity: 'high' },
  ];

  const checkPayload = (text, source) => {
    for (const { re, label, severity } of PAYLOAD) {
      if (re.test(text)) {
        findings.push({ type: 'embedded_code', detail: `${label} in ${source}: ${text.slice(0,160)}`, severity });
      }
    }
  };

  // Polyglot: secondary magic bytes embedded in file body
  // Polyglot: look for secondary format magic bytes embedded in the image body.
  // Min offset is 64 so we skip the image's own header region.
  // MZ (0x4D 0x5A) is intentionally excluded — it's only 2 bytes and appears
  // thousands of times at random in any compressed binary, causing constant false positives.
  // PE/EXE is caught instead by requiring the full DOS stub string to be present.
  const POLY = [
    { bytes: [0x25,0x50,0x44,0x46,0x2D],   label: 'PDF (%PDF-)',   sev: 'high'     }, // 5 bytes
    { bytes: [0x50,0x4B,0x03,0x04],         label: 'ZIP/JAR/APK',  sev: 'high'     }, // 4 bytes
    { bytes: [0x7F,0x45,0x4C,0x46],         label: 'ELF binary',   sev: 'critical' }, // 4 bytes
    { bytes: [0x3C,0x3F,0x70,0x68,0x70],    label: 'PHP script',   sev: 'critical' }, // 5 bytes
    { bytes: [0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1], label: 'OLE2/Office', sev: 'high' }, // 8 bytes
  ];
  for (const { bytes, label, sev } of POLY) {
    const needle = Buffer.from(bytes);
    const idx = buf.indexOf(needle, 64); // skip first 64 bytes (image header region)
    if (idx !== -1) {
      const hexSnip = [...buf.slice(idx, idx+16)].map(b=>b.toString(16).padStart(2,'0')).join(' ');
      result.polyglot_hits.push({ type: label, offset: idx, hex_preview: hexSnip });
      findings.push({ type: 'polyglot', detail: `Polyglot: ${label} magic bytes at offset ${idx} — file may be parsed by two different engines`, severity: sev });
    }
  }
  // PE/EXE polyglot: require full DOS stub string, not just MZ bytes
  if (buf.includes(Buffer.from('This program cannot be run in DOS mode'))) {
    const mzIdx = buf.indexOf(Buffer.from([0x4D,0x5A]), 64);
    if (mzIdx !== -1) {
      const hexSnip = [...buf.slice(mzIdx, mzIdx+16)].map(b=>b.toString(16).padStart(2,'0')).join(' ');
      result.polyglot_hits.push({ type: 'PE/EXE', offset: mzIdx, hex_preview: hexSnip });
      findings.push({ type: 'polyglot', detail: `Polyglot: PE/EXE (MZ + DOS stub) at offset ${mzIdx} — Windows executable embedded in image`, severity: 'critical' });
    }
  }

  // ── SVG ──────────────────────────────────────────────────────
  if (fileType === 'svg') {
    const text = buf.toString('utf8');
    const scriptRe = /<script[\s\S]*?<\/script>/gi;
    let sm;
    while ((sm = scriptRe.exec(text)) !== null) {
      result.svg_scripts.push(sm[0].slice(0, 800));
      findings.push({ type: 'svg_script', detail: `Inline <script> in SVG — executes when image is rendered in browser: ${sm[0].slice(0,160)}`, severity: 'critical' });
    }
    const evtRe = /\bon\w+\s*=\s*["'][^"']{1,300}["']/gi;
    let em;
    while ((em = evtRe.exec(text)) !== null) {
      result.svg_handlers.push(em[0].slice(0, 400));
      findings.push({ type: 'svg_handler', detail: `JS event handler in SVG attribute: ${em[0].slice(0,160)}`, severity: 'high' });
    }
    if (/href\s*=\s*["']javascript:/i.test(text)) {
      findings.push({ type: 'svg_js_uri', detail: 'javascript: URI in SVG href — executes on click or render', severity: 'high' });
    }
    const extRefs = [...text.matchAll(/(?:href|src|xlink:href)\s*=\s*["'](https?:\/\/[^"']{4,})["']/gi)].map(m=>m[1]).slice(0,10);
    if (extRefs.length) { result.svg_ext_refs = extRefs; findings.push({ type: 'svg_ext_ref', detail: `SVG loads ${extRefs.length} external resource(s): ${extRefs.slice(0,3).join(', ')}`, severity: 'medium' }); }
    checkPayload(text, 'SVG body');
    return result;
  }

  // ── JPEG ─────────────────────────────────────────────────────
  if (fileType === 'jpg') {
    let pos = 2, eoiOffset = -1;
    while (pos < buf.length - 1) {
      if (buf[pos] !== 0xFF) break;
      const marker = buf[pos+1]; pos += 2;
      if (marker === 0xD9) { eoiOffset = pos - 2; break; }
      if (marker === 0xD8 || (marker >= 0xD0 && marker <= 0xD7)) continue;
      if (pos + 2 > buf.length) break;
      const segLen = buf.readUInt16BE(pos);
      if (segLen < 2 || pos + segLen > buf.length) break;
      const seg = buf.slice(pos+2, pos+segLen); pos += segLen;

      if (marker === 0xFE) {
        const c = seg.toString('utf8').replace(/\x00/g,'').trim();
        if (c) { result.comments.push({ type:'JPEG Comment (APP-FE)', value: c }); checkPayload(c, 'JPEG Comment'); }
      }
      if (marker === 0xE1) {
        if (seg.slice(0,6).toString('binary') === 'Exif\x00\x00') {
          const ef = parseTiffIfd(seg.slice(6));
          result.exif_fields.push(...ef);
          for (const f of ef) if (typeof f.value === 'string') checkPayload(f.value, `EXIF [${f.tag}]`);
          if (ef.some(f => f.tag === 'JPEGInterchangeFormat')) result.thumbnail_present = true;
        } else if (seg.slice(0,30).toString('ascii').includes('ns.adobe.com/xap')) {
          const xf = parseXmpKeyValues(seg.toString('utf8'));
          result.xmp_fields.push(...xf);
          for (const kv of xf) checkPayload(kv.value, `XMP [${kv.key}]`);
        }
      }
      if (marker === 0xED) {
        const if2 = parseIptc(seg);
        result.iptc_fields.push(...if2);
        for (const f of if2) checkPayload(f.value, `IPTC [${f.tag}]`);
      }
      if (marker === 0xE2) result.icc_profile_kb += Math.round(seg.length/1024*10)/10;
      if (marker === 0xDA) {
        for (let i = buf.length-2; i >= pos; i--) { if (buf[i]===0xFF && buf[i+1]===0xD9) { eoiOffset=i; break; } }
        break;
      }
    }
    if (eoiOffset !== -1 && eoiOffset+2 < buf.length) {
      const app = buf.slice(eoiOffset+2);
      result.appended_data = { offset: eoiOffset+2, size: app.length, hex_dump: hexDump(app), text_preview: app.slice(0,256).toString('latin1').replace(/[^\x09\x0A\x0D\x20-\x7E]/g,'.') };
      findings.push({ type:'appended', detail:`${app.length} bytes after JPEG EOI marker at offset ${eoiOffset+2} — data exists past end of valid image`, severity: app.length>64?'critical':'high' });
      checkPayload(app.toString('latin1'), 'data appended after JPEG EOI');
    }
  }

  // ── PNG ──────────────────────────────────────────────────────
  if (fileType === 'png') {
    let pos = 8, iendEnd = -1;
    while (pos + 12 <= buf.length) {
      const chunkLen  = buf.readUInt32BE(pos);
      if (chunkLen > 50*1024*1024 || pos+8+chunkLen+4 > buf.length) break;
      const chunkType = buf.slice(pos+4, pos+8).toString('ascii');
      const chunkData = buf.slice(pos+8, pos+8+chunkLen);

      if (chunkType === 'tEXt') {
        const nul = chunkData.indexOf(0);
        if (nul !== -1) { const k=chunkData.slice(0,nul).toString('latin1'), v=chunkData.slice(nul+1).toString('latin1').trim(); result.comments.push({type:`PNG tEXt [${k}]`,value:v}); checkPayload(v,`PNG tEXt [${k}]`); }
      }
      if (chunkType === 'iTXt') {
        const nul = chunkData.indexOf(0);
        if (nul !== -1) {
          const k=chunkData.slice(0,nul).toString('latin1'), comprFlag=chunkData[nul+1]||0;
          const langEnd=chunkData.indexOf(0,nul+3), tkwEnd=langEnd!==-1?chunkData.indexOf(0,langEnd+1):-1;
          if (tkwEnd !== -1) {
            let v; try { v=comprFlag===0?chunkData.slice(tkwEnd+1).toString('utf8').trim():zlib.inflateSync(chunkData.slice(tkwEnd+1)).toString('utf8').trim(); } catch { v='(compressed)'; }
            result.comments.push({type:`PNG iTXt [${k}]`,value:v.slice(0,2000)}); checkPayload(v,`PNG iTXt [${k}]`);
          }
        }
      }
      if (chunkType === 'zTXt') {
        const nul = chunkData.indexOf(0);
        if (nul !== -1) { const k=chunkData.slice(0,nul).toString('latin1'); try { const v=zlib.inflateSync(chunkData.slice(nul+2)).toString('utf8').trim(); result.comments.push({type:`PNG zTXt [${k}]`,value:v.slice(0,2000)}); checkPayload(v,`PNG zTXt [${k}]`); } catch {} }
      }
      if (chunkType === 'iCCP') result.icc_profile_kb = Math.round(chunkLen/1024*10)/10;
      if (chunkType === 'IEND') { iendEnd = pos+4+4+chunkLen+4; break; }
      pos += 4+4+chunkLen+4;
    }
    if (iendEnd !== -1 && iendEnd < buf.length) {
      const app = buf.slice(iendEnd);
      result.appended_data = { offset: iendEnd, size: app.length, hex_dump: hexDump(app), text_preview: app.slice(0,256).toString('latin1').replace(/[^\x09\x0A\x0D\x20-\x7E]/g,'.') };
      findings.push({ type:'appended', detail:`${app.length} bytes after PNG IEND chunk at offset ${iendEnd} — data hidden past end of valid image`, severity: app.length>64?'critical':'high' });
      checkPayload(app.toString('latin1'), 'data appended after PNG IEND');
    }
  }

  // ── GIF ──────────────────────────────────────────────────────
  if (fileType === 'gif') {
    let gpos = 6;
    while (gpos < buf.length - 1) {
      if (buf[gpos] === 0x21 && buf[gpos+1] === 0xFE) {
        gpos += 2;
        let comment = '';
        while (gpos < buf.length) { const bs=buf[gpos++]; if (!bs) break; if (gpos+bs>buf.length) break; comment+=buf.slice(gpos,gpos+bs).toString('latin1'); gpos+=bs; }
        if (comment) { result.comments.push({type:'GIF Comment Extension',value:comment}); checkPayload(comment,'GIF comment'); }
      } else { gpos++; }
    }
    const trailerPos = buf.lastIndexOf(0x3B);
    if (trailerPos !== -1 && trailerPos+1 < buf.length) {
      const app = buf.slice(trailerPos+1);
      if (app.length > 0) {
        result.appended_data = { offset: trailerPos+1, size: app.length, hex_dump: hexDump(app), text_preview: app.slice(0,256).toString('latin1').replace(/[^\x09\x0A\x0D\x20-\x7E]/g,'.') };
        findings.push({ type:'appended', detail:`${app.length} bytes after GIF trailer byte at offset ${trailerPos+1}`, severity:'high' });
        checkPayload(app.toString('latin1'), 'data appended after GIF trailer');
      }
    }
  }

  // ── BMP — size declared in header, check for appended data ───
  if (fileType === 'bmp' && buf.length > 54) {
    const declared = buf.readUInt32LE(2);
    if (declared > 54 && declared < buf.length) {
      const app = buf.slice(declared);
      result.appended_data = { offset: declared, size: app.length, hex_dump: hexDump(app), text_preview: app.slice(0,256).toString('latin1').replace(/[^\x09\x0A\x0D\x20-\x7E]/g,'.') };
      findings.push({ type:'appended', detail:`${app.length} bytes past declared BMP file size at offset ${declared}`, severity:'high' });
      checkPayload(app.toString('latin1'), 'data appended past BMP declared size');
    }
  }

  // ── Steganography detection ───────────────────────────────────
  const STEGO_SIGS = [
    { str: 'OpenStegoVersion', tool: 'OpenStego',         confidence: 'certain' },
    { str: 'OpenStego',        tool: 'OpenStego',         confidence: 'high'    },
    { str: 'steghide',         tool: 'Steghide',          confidence: 'high'    },
    { str: 'Steghide',         tool: 'Steghide',          confidence: 'high'    },
    { str: 'SilentEye',        tool: 'SilentEye',         confidence: 'high'    },
    { str: 'outguess',         tool: 'OutGuess',          confidence: 'high'    },
    { str: 'OutGuess',         tool: 'OutGuess',          confidence: 'high'    },
    { str: 'jphide',           tool: 'JPHide',            confidence: 'high'    },
    { str: 'stegosuite',       tool: 'Stegosuite',        confidence: 'high'    },
    { str: 'SteganoG',         tool: 'SteganoG',          confidence: 'high'    },
    { str: 'wbStego',          tool: 'wbStego',           confidence: 'high'    },
    { str: 'InvisibleSecrets', tool: 'Invisible Secrets', confidence: 'high'    },
    { str: 'Hide4PGP',         tool: 'Hide4PGP',          confidence: 'high'    },
    { str: 'S-Tools',          tool: 'S-Tools',           confidence: 'high'    },
    { str: 'HIDETHERE',        tool: 'HideThere',         confidence: 'high'    },
    { str: 'Camouflage',       tool: 'Camouflage',        confidence: 'medium'  },
  ];

  const stego = { tool_signatures: [], lsb: null, jpeg_note: null };
  result.stego = stego;

  const rawLatin = buf.toString('latin1');
  for (const { str, tool, confidence } of STEGO_SIGS) {
    if (rawLatin.includes(str)) {
      stego.tool_signatures.push({ tool, confidence, pattern: str });
      findings.push({
        type: 'stego_signature', severity: confidence === 'certain' ? 'critical' : 'high',
        detail: `Steganography tool signature: ${tool} (matched "${str}")`,
      });
    }
  }

  if (fileType === 'png') {
    const lsb = extractPngLsb(buf);
    stego.lsb = lsb;
    if (lsb) {
      if (lsb.embedded_magic) {
        findings.push({ type:'stego_lsb', severity:'critical',
          detail:`PNG LSB stream starts with ${lsb.embedded_magic} magic bytes — embedded file detected in pixel LSBs` });
      } else if (lsb.readable_text) {
        findings.push({ type:'stego_lsb', severity:'critical',
          detail:`PNG LSB extraction found readable text in pixel data (printable ratio ${lsb.printable_ratio})` });
      } else if (lsb.suspicious) {
        findings.push({ type:'stego_lsb', severity:'medium',
          detail:`PNG pixel LSBs are statistically uniform (chi²=${lsb.chi2}) — consistent with LSB steganography` });
      }
    }
  }

  if (fileType === 'jpg') {
    stego.jpeg_note = 'JPEG pixel-level LSB analysis requires `npm install sharp`. DCT-coefficient stego (Steghide, OutGuess, JSteg) cannot be detected without a full JPEG entropy decoder.';
  }

  return result;
}

// ── Hash tool helpers ─────────────────────────────────────────

function identifyHash(h) {
  const s = h.trim();
  const candidates = [];
  if (/^\$2[aby]\$\d{2}\$.{53}$/.test(s))       candidates.push({ type:'bcrypt',              bits:null, confidence:'certain' });
  if (/^\$1\$[^\$]+\$[a-zA-Z0-9./]{22}$/.test(s)) candidates.push({ type:'MD5-crypt (Unix $1$)',bits:null, confidence:'certain' });
  if (/^\$5\$/.test(s))                           candidates.push({ type:'SHA-256-crypt ($5$)', bits:null, confidence:'certain' });
  if (/^\$6\$/.test(s))                           candidates.push({ type:'SHA-512-crypt ($6$)', bits:null, confidence:'certain' });
  if (/^\$argon2/.test(s))                        candidates.push({ type:'Argon2',              bits:null, confidence:'certain' });
  if (/^\$pbkdf2/.test(s))                        candidates.push({ type:'PBKDF2',              bits:null, confidence:'certain' });
  if (/^[a-f0-9]{8}$/i.test(s))                  candidates.push({ type:'CRC32',               bits:32,   confidence:'medium'  });
  if (/^[a-f0-9]{16}$/i.test(s))                  candidates.push({ type:'MySQL 3.x / Half-MD5',bits:64,   confidence:'medium'  });
  if (/^[a-f0-9]{32}$/i.test(s))                  candidates.push({ type:'MD5',                 bits:128,  confidence:'high'    });
  if (/^[a-f0-9]{40}$/i.test(s))                  candidates.push({ type:'SHA-1',               bits:160,  confidence:'high'    });
  if (/^[a-f0-9]{56}$/i.test(s))                  candidates.push({ type:'SHA-224',             bits:224,  confidence:'high'    });
  if (/^[a-f0-9]{64}$/i.test(s))                  candidates.push({ type:'SHA-256 / SHA-3-256', bits:256,  confidence:'high'    });
  if (/^[a-f0-9]{96}$/i.test(s))                  candidates.push({ type:'SHA-384',             bits:384,  confidence:'high'    });
  if (/^[a-f0-9]{128}$/i.test(s))                 candidates.push({ type:'SHA-512 / SHA-3-512', bits:512,  confidence:'high'    });
  if (/^[a-f0-9]{32}$/i.test(s) && /^[A-F0-9]+$/.test(s)) candidates.push({ type:'MD5 (uppercase)', bits:128, confidence:'high' });
  if (/^[a-zA-Z0-9+\/]{43}=$/.test(s))           candidates.push({ type:'SHA-256 (Base64)',    bits:256,  confidence:'medium'  });
  if (/^[a-zA-Z0-9+\/]{86}==?$/.test(s))         candidates.push({ type:'SHA-512 (Base64)',    bits:512,  confidence:'medium'  });
  if (candidates.length === 0) candidates.push({ type:'Unknown — not a recognised hash format', bits:null, confidence:'none' });
  return candidates;
}

// Top-500 most common passwords for bundled wordlist cracking
const COMMON_PASSWORDS = [
  'password','123456','password123','12345678','qwerty','111111','1234567890','1234567',
  'abc123','monkey','letmein','1234','dragon','master','666666','qwertyuiop','123321',
  'mustang','000000','trustno1','iloveyou','sunshine','princess','welcome','shadow',
  'superman','michael','football','baseball','liverpool','charlie','donald','password1',
  'qwerty123','admin','login','hello','12345','54321','test','pass','secret','access',
  '696969','aaaaaa','matrix','corvette','ginger','thomas','hunter','ranger','joshua',
  'hannah','cheese','butter','soccer','harley','dakota','batman','george','wizard',
  'phoenix','jessica','taylor','jordan','austin','tiger','zxcvbn','james','junior',
  'passw0rd','Password1','changeme','temp','letmein1','abc1234','1q2w3e4r','qazwsx',
  'asdfgh','zxcvbn','123qwe','1qaz2wsx','test123','admin123','root','toor','alpine',
  'raspberry','ubuntu','debian','centos','fedora','redhat','windows','linux','android',
  'apple','google','facebook','twitter','instagram','youtube','amazon','netflix','spotify',
  'myspace','yahoo','hotmail','gmail','outlook','icloud','dropbox','github','gitlab',
  'stackoverflow','reddit','discord','telegram','whatsapp','signal','skype','zoom',
  'nintendo','playstation','xbox','minecraft','roblox','fortnite','pokemon','pikachu',
  'pokemon123','mario','zelda','sonic','batman1','superman1','spiderman','ironman',
  'captain','avenger','hulk','thor','loki','wolverine','deadpool','venom','joker',
  'harley','quinn','batman2','batman3','catwoman','penguin','riddler','bane',
  'starwars','luke','vader','jedi','sith','r2d2','c3po','yoda','obiwan','anakin',
  'leia','han','solo','chewbacca','falcon','mandalorian','grogu','babyyoda',
  'password2','password3','password!','P@ssword','P@ss123','P@ssw0rd','Pa$$word',
  'Pa$$w0rd','Passw0rd!','passworD','PASSWORD','QWERTY','LETMEIN','ADMIN',
  '12345678901','123456789012','1234567890123','qwertyuiop[]','asdfghjkl;',
  'zxcvbnm,./','!@#$%^&*','abcdefgh','abcdefg','abcdef','12341234','11111111',
  '22222222','33333333','44444444','55555555','77777777','88888888','99999999',
  '10203040','11223344','112233','123123123','321321','654321','987654','741852',
  'q1w2e3r4','1q2w3e','qazxsw','aaabbb','aabbcc','abcabc','abc123abc','Pass1234',
  'Summer2023','Summer2024','Winter2023','Winter2024','Spring2024','Fall2023',
  'January1','February1','March2023','Admin1234','Admin@123','Welcome1','Welcome123',
  'Company1','company123','Default1','default123','changeit','change123','newpass',
  'newpassword','mypassword','mypassword1','mypass123','pass1234','pass@word1',
  'Password@1','P@ssword1','Passw0rd1','password01','password!1','p@ssw0rd',
  'monkey123','dragon123','shadow123','master123','tiger123','ranger123','hunter123',
  'silver','golden','black','white','blue','green','red','purple','orange','yellow',
  'love','hate','life','death','time','space','world','earth','moon','star',
  'sun','fire','water','wind','thunder','lightning','storm','snow','rain','cloud',
  'ocean','river','mountain','forest','desert','jungle','island','valley','canyon',
  'secret123','private','hidden','unknown','nothing','something','everything','nobody',
  'somebody','anybody','everyone','everyone1','noone','nowhere','somewhere','anywhere',
  'forever','never','always','sometimes','often','rarely','usually','mostly',
  'baseball1','football1','soccer1','hockey1','tennis1','golf1','boxing1','rugby1',
  'cricket1','basketball1','volleyball1','swimming1','running1','cycling1','hiking1',
];

function crackWithWordlist(targetHash, algorithm) {
  const crypto = require('crypto');
  const algs = algorithm ? [algorithm] : ['md5','sha1','sha256','sha512'];
  for (const alg of algs) {
    for (const word of COMMON_PASSWORDS) {
      if (crypto.createHash(alg).update(word).digest('hex') === targetHash.toLowerCase()) {
        return { plaintext: word, algorithm: alg };
      }
    }
  }
  return null;
}

async function crackWithRainbowTable(targetHash, filePath, algorithm) {
  if (!fs.existsSync(filePath)) return null;
  const readline  = require('readline');
  const crypto    = require('crypto');
  const algs      = algorithm ? [algorithm] : ['md5','sha1','sha256','sha512'];
  const targetLow = targetHash.toLowerCase();

  return new Promise(resolve => {
    const rl = readline.createInterface({
      input: fs.createReadStream(filePath, { encoding: 'utf8' }),
      crlfDelay: Infinity,
    });
    let found = null;
    let isPrecomputed = null;
    let lineCount = 0;

    rl.on('line', line => {
      if (found) return;
      line = line.trim();
      if (!line || line.startsWith('#')) return;
      lineCount++;

      // Auto-detect format from first real line
      if (isPrecomputed === null) {
        isPrecomputed = /^[a-f0-9]{16,128}:/i.test(line);
      }

      if (isPrecomputed) {
        // hash:plaintext — direct lookup
        const col = line.indexOf(':');
        if (col === -1) return;
        if (line.slice(0, col).toLowerCase() === targetLow) {
          found = { plaintext: line.slice(col + 1), method: 'rainbow_precomputed', lines_searched: lineCount };
          rl.close();
        }
      } else {
        // Wordlist — compute and compare
        for (const alg of algs) {
          try {
            if (crypto.createHash(alg).update(line).digest('hex') === targetLow) {
              found = { plaintext: line, algorithm: alg, method: 'rainbow_wordlist', lines_searched: lineCount };
              rl.close();
              return;
            }
          } catch {}
        }
      }
    });

    rl.on('close', () => resolve(found));
    rl.on('error', () => resolve(null));
  });
}

// ── Scan API handlers ─────────────────────────────────────────
const MOCKS = {

  'hash.php': async ({ action, text, algorithm, key, inputHash } = {}) => {
    const crypto = require('crypto');

    // ── status: rainbow table info ────────────────────────────
    if (action === 'status') {
      const exists = fs.existsSync(RAINBOW_TABLE_PATH);
      let lines = 0, size_mb = 0, format = null;
      if (exists) {
        const stat = fs.statSync(RAINBOW_TABLE_PATH);
        size_mb = Math.round(stat.size / 1024 / 1024 * 10) / 10;
        // Peek at first line to detect format
        const firstLine = await new Promise(r => {
          const rl = require('readline').createInterface({ input: fs.createReadStream(RAINBOW_TABLE_PATH, { encoding: 'utf8' }) });
          rl.once('line', l => { rl.close(); r(l.trim()); });
          rl.on('error', () => r(null));
        });
        if (firstLine) format = /^[a-f0-9]{16,128}:/i.test(firstLine) ? 'precomputed' : 'wordlist';
      }
      return { configured: exists, path: RAINBOW_TABLE_PATH, size_mb, format, wordlist_entries: COMMON_PASSWORDS.length };
    }

    // ── hash: generate all digests ────────────────────────────
    if (action === 'hash') {
      if (!text && text !== '0') return { error: 'No input text provided' };
      const input = String(text);
      return {
        input,
        hashes: {
          md5:    crypto.createHash('md5').update(input).digest('hex'),
          sha1:   crypto.createHash('sha1').update(input).digest('hex'),
          sha256: crypto.createHash('sha256').update(input).digest('hex'),
          sha384: crypto.createHash('sha384').update(input).digest('hex'),
          sha512: crypto.createHash('sha512').update(input).digest('hex'),
        },
      };
    }

    // ── hmac: keyed hash ──────────────────────────────────────
    if (action === 'hmac') {
      if (!text) return { error: 'No input text provided' };
      if (!key)  return { error: 'No HMAC key provided' };
      const alg = (algorithm || 'sha256').toLowerCase();
      if (!['md5','sha1','sha256','sha384','sha512'].includes(alg)) return { error: `Unsupported HMAC algorithm: ${alg}` };
      return {
        input: text, key, algorithm: 'HMAC-' + alg.toUpperCase(),
        hash: crypto.createHmac(alg, key).update(text).digest('hex'),
      };
    }

    // ── identify: what type is this hash? ─────────────────────
    if (action === 'identify') {
      if (!inputHash) return { error: 'No hash provided' };
      return { input: inputHash, candidates: identifyHash(inputHash) };
    }

    // ── crack: wordlist + optional rainbow table ───────────────
    if (action === 'crack') {
      if (!inputHash) return { error: 'No hash provided' };
      const h   = inputHash.trim().toLowerCase();
      const ids = identifyHash(h);
      const alg = algorithm && algorithm !== 'auto'
        ? algorithm
        : ids.find(c => ['md5','sha1','sha256','sha384','sha512'].includes(
            (c.type.split(' ')[0]).toLowerCase().replace('-','')
          ))?.type.split(' ')[0].toLowerCase().replace('-','') || null;

      // 1. Bundled wordlist
      const wl = crackWithWordlist(h, alg);
      if (wl) return { cracked: true, plaintext: wl.plaintext, algorithm: wl.algorithm, method: 'bundled_wordlist', candidates: ids };

      // 2. Rainbow table (if configured)
      const rtExists = fs.existsSync(RAINBOW_TABLE_PATH);
      if (rtExists) {
        const rt = await crackWithRainbowTable(h, RAINBOW_TABLE_PATH, alg);
        if (rt) return { cracked: true, plaintext: rt.plaintext, algorithm: rt.algorithm || alg, method: rt.method, lines_searched: rt.lines_searched, candidates: ids };
      }

      return {
        cracked: false,
        candidates: ids,
        tried: { wordlist: true, wordlist_size: COMMON_PASSWORDS.length, rainbow_table: rtExists },
        rainbow_table_path: RAINBOW_TABLE_PATH,
        note: rtExists
          ? 'Not found in bundled wordlist or rainbow table'
          : 'Not found in bundled wordlist. Configure a rainbow table for deeper cracking.',
      };
    }

    return { error: 'Unknown action' };
  },

  'scan_file.php': ({ file } = {}) => {
    const crypto = require('crypto');
    const path   = require('path');

    if (!file || !file.buffer || !file.filename) {
      return { error: 'No file received. Select a file and try again.' };
    }

    const { filename, buffer, size } = file;
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
    const md5    = crypto.createHash('md5').update(buffer).digest('hex');
    const ext    = path.extname(filename).toLowerCase().replace('.', '');

    // ── Magic bytes → real file type ──────────────────────────
    const magic = buffer.slice(0, 8).toString('hex');
    const MAGIC_MAP = [
      { hex: '25504446',  mime: 'application/pdf',           type: 'pdf',   label: 'PDF Document'           },
      { hex: '504b0304',  mime: 'application/zip',           type: 'zip',   label: 'ZIP Archive'            },
      { hex: 'd0cf11e0',  mime: 'application/msword',        type: 'ole',   label: 'OLE2 (DOC/XLS/PPT)'     },
      { hex: '25215053',  mime: 'application/postscript',    type: 'ps',    label: 'PostScript'             },
      { hex: '4d5a',      mime: 'application/x-msdownload',  type: 'exe',   label: 'Windows PE Executable'  },
      { hex: '7f454c46',  mime: 'application/x-elf',         type: 'elf',   label: 'Linux ELF Executable'   },
      { hex: 'cafebabe',  mime: 'application/java',          type: 'class', label: 'Java Class'             },
      { hex: '3c3f786d',  mime: 'text/xml',                  type: 'xml',   label: 'XML Document'           },
      { hex: '3c68746d',  mime: 'text/html',                 type: 'html',  label: 'HTML Document'          },
      { hex: 'ffd8ff',    mime: 'image/jpeg',                type: 'jpg',   label: 'JPEG Image'             },
      { hex: '89504e47',  mime: 'image/png',                 type: 'png',   label: 'PNG Image'              },
      { hex: '47494638',  mime: 'image/gif',                 type: 'gif',   label: 'GIF Image'              },
      { hex: '424d',      mime: 'image/bmp',                 type: 'bmp',   label: 'BMP Image'              },
      { hex: '52494646',  mime: 'image/webp',                type: 'webp',  label: 'WebP Image'             },
    ];
    let detectedMime  = 'application/octet-stream';
    let fileType      = 'binary';
    let fileTypeLabel = 'Unknown Binary';
    for (const m of MAGIC_MAP) {
      if (magic.startsWith(m.hex)) {
        detectedMime  = m.mime;
        fileType      = m.type;
        fileTypeLabel = m.label;
        break;
      }
    }

    // SVG detection — text-based format, no fixed magic bytes
    if ((ext === 'svg' || fileType === 'xml') && /\<svg[\s>]/i.test(content.slice(0, 2000))) {
      fileType = 'svg'; fileTypeLabel = 'SVG Image'; detectedMime = 'image/svg+xml';
    }

    // ── Extension vs magic mismatch check ────────────────────
    const EXT_EXPECTED = { pdf:'pdf', doc:'ole', docx:'zip', xls:'ole', xlsx:'zip',
                           ppt:'ole', pptx:'zip', jar:'zip', apk:'zip', epub:'zip',
                           exe:'exe', elf:'elf', ps:'ps', html:'html', htm:'html',
                           jpg:'jpg', jpeg:'jpg', png:'png', gif:'gif', bmp:'bmp', svg:'svg' };
    const expectedType   = EXT_EXPECTED[ext] || null;
    const extensionSpoof = expectedType && expectedType !== fileType;

    // ── Shannon entropy (high = obfuscated/encrypted/compressed) ─
    function entropy(buf) {
      const freq = new Array(256).fill(0);
      for (let i = 0; i < buf.length; i++) freq[buf[i]]++;
      let e = 0;
      for (const f of freq) {
        if (f === 0) continue;
        const p = f / buf.length;
        e -= p * Math.log2(p);
      }
      return Math.round(e * 100) / 100;
    }
    const fileEntropy = entropy(buffer);
    // Sample first 4KB for header entropy separately
    const headerEntropy = buffer.length > 64 ? entropy(buffer.slice(0, Math.min(4096, buffer.length))) : fileEntropy;

    // latin1 = safe byte-for-byte string access for pattern matching
    const content  = buffer.toString('latin1');
    const findings = [];

    // ── PDF dangerous objects ─────────────────────────────────
    const PDF_KEYS = {
      '/OpenAction': { sev: 'high',     desc: 'Auto-executes action on PDF open' },
      '/AA':         { sev: 'high',     desc: 'Additional Actions — event-triggered execution' },
      '/JS':         { sev: 'high',     desc: 'JavaScript present in PDF structure' },
      '/JavaScript': { sev: 'high',     desc: 'JavaScript stream object' },
      '/Launch':     { sev: 'critical', desc: 'Can launch external applications' },
      '/EmbeddedFile':{ sev: 'low',    desc: 'Contains embedded file — inspect if unexpected' },
      '/RichMedia':  { sev: 'low',    desc: 'Flash / multimedia content (legacy)' },
      '/JBIG2Decode':{ sev: 'high',   desc: 'JBIG2 compression — CVE-2023-3420 family' },
      '/XFA':        { sev: 'low',    desc: 'XML Forms Architecture (common in fillable forms)' },
      '/ObjStm':     { sev: 'low',      desc: 'Object stream — can conceal objects from parsers' },
      '/Encrypt':    { sev: 'low',      desc: 'PDF is encrypted — content hidden from analysis' },
    };
    const pdfParsed = {};
    if (fileType === 'pdf') {
      for (const [key, info] of Object.entries(PDF_KEYS)) {
        const count = (content.match(new RegExp(key.replace('/', '\\/'), 'g')) || []).length;
        pdfParsed[key] = count;
        if (count > 0) {
          findings.push({ type: 'pdfid', detail: `${key}: ${count} occurrence(s) — ${info.desc}`, severity: info.sev });
        }
      }
      // PDF page count
      const pageCount = (content.match(/\/Type\s*\/Page[^s]/g) || []).length;
      pdfParsed._pages = pageCount;

      // PDF metadata extraction
      const titleM    = content.match(/\/Title\s*\(([^)]{1,120})\)/);
      const authorM   = content.match(/\/Author\s*\(([^)]{1,120})\)/);
      const creatorM  = content.match(/\/Creator\s*\(([^)]{1,120})\)/);
      const producerM = content.match(/\/Producer\s*\(([^)]{1,120})\)/);
      const createdM  = content.match(/\/CreationDate\s*\(([^)]{1,40})\)/);
      const modifiedM = content.match(/\/ModDate\s*\(([^)]{1,40})\)/);
      pdfParsed._meta = {
        title:    titleM    ? titleM[1]    : null,
        author:   authorM   ? authorM[1]   : null,
        creator:  creatorM  ? creatorM[1]  : null,
        producer: producerM ? producerM[1] : null,
        created:  createdM  ? createdM[1]  : null,
        modified: modifiedM ? modifiedM[1] : null,
      };
    }

    // ── OLE2 macro indicators (DOC/XLS/PPT) ──────────────────
    if (fileType === 'ole') {
      const macroStreams = ['Macros', 'VBA', '_VBA_PROJECT', 'ThisWorkbook', 'Module'];
      for (const s of macroStreams) {
        if (content.includes(s)) {
          findings.push({ type: 'macro', detail: `OLE stream "${s}" found — may contain VBA macros`, severity: 'high' });
        }
      }
      if (content.includes('AutoOpen') || content.includes('AutoExec') || content.includes('Document_Open')) {
        findings.push({ type: 'macro', detail: 'Auto-execution macro trigger found (AutoOpen/AutoExec/Document_Open)', severity: 'critical' });
      }
    }

    // ── Executable indicators ─────────────────────────────────
    if (fileType === 'exe' || fileType === 'elf') {
      findings.push({ type: 'executable', detail: `File is a ${fileTypeLabel} — direct execution risk`, severity: 'critical' });
    }

    // ── Extension spoof ───────────────────────────────────────
    if (extensionSpoof) {
      findings.push({
        type: 'spoof',
        detail: `Extension .${ext} claims ${ext.toUpperCase()} but magic bytes identify file as ${fileTypeLabel} — possible disguise`,
        severity: 'critical',
      });
    }

    // ── High entropy — informational only, NOT a verdict raiser ─
    // Compressed image formats (JPEG, PNG, GIF, WebP) naturally score 7.5–8.0.
    // Only flag for non-compressed, non-image types.
    const IMAGE_TYPES = new Set(['jpg','png','gif','bmp','webp','svg']);
    const compressedTypes = new Set(['zip','pdf','jpg','png','gif','webp']);
    if (fileEntropy > 7.2 && !compressedTypes.has(fileType)) {
      findings.push({ type: 'entropy', detail: `High entropy (${fileEntropy}/8.0) — content may be encrypted or packed`, severity: 'medium' });
    } else if (fileEntropy > 7.5 && !IMAGE_TYPES.has(fileType)) {
      findings.push({ type: 'entropy', detail: `Entropy ${fileEntropy}/8.0 — expected for compressed format`, severity: 'info' });
    }

    // ── Suspicious string patterns ────────────────────────────
    // Skipped for image types — compressed pixel data produces constant false positives
    // (random bytes form accidental regex matches). Image metadata is scanned separately
    // in analyzeImage() which runs only on metadata regions (EXIF, comments, chunks).
    const STR_PATTERNS = {
      'JS eval/exec':          { re: /eval\s*\(|eval\s*\[|new\s+Function\s*\(/gi,                                  sev: 'high',     info: false },
      'Shell command':         { re: /(cmd\.exe|powershell|\/bin\/sh|\/bin\/bash|wget\s|curl\s)/gi,                 sev: 'critical', info: false },
      'Credential in text':    { re: /(password|passwd|api[_\-]?key|secret|token)\s*[=:]\s*["'][^"']{4,}/gi,       sev: 'high',     info: false },
      'Hex shellcode':         { re: /((?:\\x[0-9a-f]{2}){8,})/gi,                                                 sev: 'high',     info: false },
      'IP address':            { re: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g, sev: 'low', info: true  },
      'Registry key':          { re: /HKEY_(LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS)[\\\/][^\s"']{4,}/gi,    sev: 'medium',   info: false },
      'System path':           { re: /(%APPDATA%|%TEMP%|%WINDIR%|C:\\Windows|\/etc\/passwd|\/etc\/shadow)/gi,      sev: 'medium',   info: false },
      'Suspicious URL':        { re: /https?:\/\/[^\s"'<>]{10,}/g,                                                 sev: 'info',     info: true  },
    };
    const strHits = {};
    if (!IMAGE_TYPES.has(fileType)) {
      for (const [name, { re, sev, info }] of Object.entries(STR_PATTERNS)) {
        const matches = [...new Set((content.match(re) || []).map(m => m.trim()))].slice(0, 8);
        strHits[name] = matches;
        if (matches.length > 0) {
          findings.push({
            type: info ? 'info' : 'strings',
            detail: `${name}: ${matches.length} occurrence(s)`,
            severity: sev,
          });
        }
      }
    }

    // ── Extracted URLs ────────────────────────────────────────
    const urlMatches = !IMAGE_TYPES.has(fileType)
      ? [...new Set((content.match(/https?:\/\/[^\s"'<>)\]]{8,}/g) || []))].slice(0, 20)
      : [];

    // ── Image-specific analysis ───────────────────────────────
    let image_analysis = null;
    if (IMAGE_TYPES.has(fileType)) {
      image_analysis = analyzeImage(buffer, fileType);
      for (const f of image_analysis.findings) findings.push(f);
    }

    // ── Verdict — only raise on genuinely malicious patterns ──
    const SEV_ORDER  = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const RAISE_VERDICT_TYPES = ['pdfid', 'macro', 'executable', 'spoof', 'strings',
                                  'embedded_code', 'polyglot', 'appended', 'svg_script', 'svg_handler', 'svg_js_uri',
                                  'stego_signature', 'stego_lsb'];
    const verdictFindings = findings.filter(f => RAISE_VERDICT_TYPES.includes(f.type) && SEV_ORDER[f.severity] >= 2);
    const maxSevNum  = findings.reduce((a, f) => Math.max(a, SEV_ORDER[f.severity] || 0), 0);
    const maxSev     = Object.keys(SEV_ORDER).find(k => SEV_ORDER[k] === maxSevNum) || 'info';
    const verdict    = maxSevNum >= 4 ? 'malicious'
                     : verdictFindings.length > 0 ? 'suspicious'
                     : 'clean';

    return {
      filename,
      size,
      mime:           detectedMime,
      file_type:      fileTypeLabel,
      extension:      ext || '(none)',
      extension_spoof: extensionSpoof,
      sha256,
      md5,
      entropy:        fileEntropy,
      header_entropy: headerEntropy,
      verdict,
      severity:       verdict === 'clean' ? 'info' : maxSev,
      findings,
      extracted_urls: urlMatches,
      clamav: {
        clean: true,
        detections: [],
        raw: `${filename}: OK\n[Dev mode — ClamAV runs on production server only]`,
      },
      pdfid: fileType === 'pdf' ? {
        raw: `[Dev mode — full pdfid.py analysis runs on production server]\n\n` +
             Object.entries(pdfParsed)
               .filter(([k]) => !k.startsWith('_'))
               .map(([k, v]) => ` ${k.padEnd(16)} ${v}`)
               .join('\n'),
        findings: findings.filter(f => f.type === 'pdfid'),
        parsed:   pdfParsed,
        meta:     pdfParsed._meta || null,
        pages:    pdfParsed._pages || 0,
      } : null,
      strings:        { hits: strHits, total_scanned: size },
      image_analysis: image_analysis,
      virustotal: {
        found: false,
        note: 'VirusTotal hash lookup requires VT_API_KEY on production server',
        sha256,
      },
    };
  },

  'scan_url.php': async ({ url } = {}) => {
    const dns = require('dns').promises;
    if (!url || url === 'undefined') return { error: 'No URL provided' };

    let parsed;
    try { parsed = new URL(url.startsWith('http') ? url : 'https://' + url); }
    catch { return { error: 'Invalid URL format' }; }
    const domain = parsed.hostname;

    // Resolve IP
    let resolvedIp = null;
    try { resolvedIp = (await dns.lookup(domain)).address; } catch {}

    // Fetch the URL — get real status + headers
    let resp = null;
    try { resp = await httpGet(parsed.href, { timeout: 8000 }); }
    catch (e) { resp = { status: null, headers: {}, body: '', error: e.message }; }

    // URLhaus lookup — free API, no key
    let urlhaus = { status: 'not_in_db', threat: null, tags: [], link: null };
    try {
      const uhResp = await httpGet('https://urlhaus-api.abuse.ch/v1/url/', {
        method: 'POST',
        body:   `url=${encodeURIComponent(parsed.href)}`,
        extraHeaders: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 8000,
      });
      const uh = JSON.parse(uhResp.body);
      if (uh.query_status === 'is_available') {
        urlhaus = { status: uh.url_status || 'in_db', threat: uh.threat, tags: uh.tags || [], link: uh.urlhaus_reference };
      }
    } catch {}

    // Build findings
    const findings = [];
    let verdict = 'clean', severity = 'info';

    if (urlhaus.status !== 'not_in_db') {
      findings.push({ type: 'urlhaus', detail: `URL in URLhaus malware database — threat: ${urlhaus.threat || 'unknown'}`, severity: 'critical' });
      verdict = 'malicious'; severity = 'critical';
    }
    if (resp?.status >= 500) {
      findings.push({ type: 'http', detail: `Server error HTTP ${resp.status}`, severity: 'medium' });
    }
    if (resp?.finalUrl && resp.finalUrl !== parsed.href) {
      findings.push({ type: 'redirect', detail: `Redirects to: ${resp.finalUrl}`, severity: 'info' });
    }
    if (findings.length === 0) {
      findings.push({ type: 'clean', detail: 'Not found in threat intelligence databases', severity: 'info' });
    }

    return {
      url:         parsed.href,
      domain,
      resolved_ip: resolvedIp || 'Could not resolve',
      verdict, severity, findings,
      urlhaus,
      virustotal: { found: false, note: 'VirusTotal requires VT_API_KEY in config.php' },
      gsb:        { note: 'Google Safe Browsing requires GSB_API_KEY in config.php'    },
      abuseipdb:  { note: 'AbuseIPDB requires ABUSEIPDB_KEY in config.php'             },
      headers:    { http_code: resp?.status || null, server: resp?.headers?.server || null, content_type: resp?.headers?.['content-type'] || null },
    };
  },

  'scan_site.php': async ({ url } = {}) => {
    const tls = require('tls');
    if (!url || url === 'undefined') return { error: 'No URL provided' };

    let baseUrl;
    try { baseUrl = new URL(url.startsWith('http') ? url : 'https://' + url); }
    catch { return { error: 'Invalid URL' }; }
    const target = baseUrl.origin;
    const domain = baseUrl.hostname;

    // 1. Fetch main page
    let mainResp = null;
    try { mainResp = await httpGet(target + '/', { timeout: 10000 }); }
    catch (e) { mainResp = { status: null, headers: {}, body: '', error: e.message }; }
    const rh = mainResp?.headers || {};

    // 2. SSL certificate via TLS
    let ssl = null;
    if (baseUrl.protocol === 'https:') {
      ssl = await new Promise(resolve => {
        const port = parseInt(baseUrl.port) || 443;
        const sock = tls.connect({ host: domain, port, servername: domain, rejectUnauthorized: false, timeout: 6000 }, () => {
          const cert = sock.getPeerCertificate(true);
          sock.destroy();
          if (!cert?.subject) return resolve(null);
          const expires  = new Date(cert.valid_to);
          const daysLeft = Math.floor((expires - Date.now()) / 86400000);
          resolve({
            valid:     true,
            expires:   cert.valid_to,
            days_left: daysLeft,
            issuer:    cert.issuer?.O || cert.issuer?.CN || 'Unknown',
            subject:   cert.subject?.CN || domain,
            san:       cert.subjectaltname || `DNS:${domain}`,
          });
        });
        sock.on('error', () => resolve(null));
        sock.on('timeout', () => { sock.destroy(); resolve(null); });
      });
    }

    // 3. Security header analysis
    const SEC_HDRS = [
      { header: 'strict-transport-security', name: 'HSTS',                    risk: 'high'   },
      { header: 'x-frame-options',           name: 'X-Frame-Options',         risk: 'medium' },
      { header: 'x-content-type-options',    name: 'X-Content-Type-Options',  risk: 'low'    },
      { header: 'content-security-policy',   name: 'Content-Security-Policy', risk: 'medium' },
      { header: 'referrer-policy',           name: 'Referrer-Policy',         risk: 'low'    },
      { header: 'permissions-policy',        name: 'Permissions-Policy',      risk: 'low'    },
    ];
    const LEAKY_HDRS = ['server','x-powered-by','x-aspnet-version','x-aspnetmvc-version','x-generator'];
    const headers = SEC_HDRS.map(h => ({
      header: h.header, name: h.name,
      present: !!rh[h.header],
      risk:    rh[h.header] ? 'none' : h.risk,
      value:   rh[h.header] || null,
    }));

    // 4. Probe sensitive paths in parallel
    const PATHS = [
      { path: '/.env',                  label: '.env file',           severity: 'critical' },
      { path: '/.git/HEAD',             label: '.git directory',      severity: 'critical' },
      { path: '/config.php',            label: 'config.php',          severity: 'critical' },
      { path: '/phpinfo.php',           label: 'phpinfo()',           severity: 'critical' },
      { path: '/adminer.php',           label: 'Adminer',            severity: 'critical' },
      { path: '/phpmyadmin/',           label: 'phpMyAdmin',         severity: 'critical' },
      { path: '/backup.sql',            label: 'SQL backup',          severity: 'critical' },
      { path: '/web.config',            label: 'web.config',          severity: 'critical' },
      { path: '/server-status',         label: 'Apache server-status',severity: 'high'     },
      { path: '/xmlrpc.php',            label: 'XML-RPC',             severity: 'high'     },
      { path: '/wp-json/wp/v2/users',   label: 'WP user enumeration', severity: 'high'     },
      { path: '/wp-login.php',          label: 'WP login page',       severity: 'medium'   },
      { path: '/wp-admin/',             label: 'WP admin',            severity: 'medium'   },
      { path: '/wp-json/',              label: 'WP REST API',         severity: 'info'     },
      { path: '/wp-content/debug.log',  label: 'WP debug.log',       severity: 'critical' },
      { path: '/robots.txt',            label: 'robots.txt',          severity: 'info'     },
      { path: '/sitemap.xml',           label: 'sitemap.xml',         severity: 'info'     },
      { path: '/admin/',                label: 'Admin panel',         severity: 'medium'   },
      { path: '/swagger.json',          label: 'Swagger/OpenAPI spec',severity: 'medium'   },
      { path: '/graphql',               label: 'GraphQL endpoint',    severity: 'info'     },
    ];
    const probeResults = await Promise.allSettled(PATHS.map(async p => {
      try {
        const r = await httpGet(target + p.path, { timeout: 5000, maxRedirects: 0 });
        return { ...p, code: r.status, url: target + p.path };
      } catch { return { ...p, code: null, url: target + p.path }; }
    }));
    const probed = probeResults.map(r => r.value).filter(Boolean);

    // 5. Detect CMS from page body + headers
    const body = mainResp?.body || '';
    const isWP = /wp-content|wp-includes|xmlrpc\.php|\/wp-json\//i.test(body) || !!rh['x-pingback'];

    // 6. Build findings
    const findings = [];
    for (const h of headers) {
      if (!h.present) findings.push({ type: 'headers', detail: `Missing security header: ${h.name}`, severity: h.risk });
    }
    for (const lh of LEAKY_HDRS) {
      if (rh[lh]) findings.push({ type: 'headers', detail: `Server leaks [${lh}: ${rh[lh]}]`, severity: 'low' });
    }
    for (const p of probed) {
      if (p.code === 200) {
        findings.push({ type: 'probe', detail: `${p.label} (${p.path}) — HTTP 200 accessible`, severity: p.severity, url: p.url });
      } else if (p.code === 403 && ['critical','high'].includes(p.severity)) {
        findings.push({ type: 'probe', detail: `${p.label} (${p.path}) — exists but access blocked (HTTP 403)`, severity: 'low', url: p.url });
      }
    }
    if (!ssl) {
      findings.push({ type: 'ssl', detail: 'SSL/TLS unavailable or unverifiable', severity: 'high' });
    } else if (ssl.days_left < 14) {
      findings.push({ type: 'ssl', detail: `SSL expires in ${ssl.days_left} days — URGENT`, severity: 'critical' });
    } else if (ssl.days_left < 30) {
      findings.push({ type: 'ssl', detail: `SSL expires in ${ssl.days_left} days`, severity: 'high' });
    }

    const sevW = { critical: 20, high: 10, medium: 5, low: 2, info: 0 };
    const score = Math.max(0, 100 - findings.reduce((s, f) => s + (sevW[f.severity] || 0), 0));

    return {
      target, domain, score, findings, isWP,
      ssl:     ssl || { error: 'No SSL certificate' },
      headers,
      missing: headers.filter(h => !h.present).map(h => h.name),
      probed,
    };
  },

  'osint.php': async ({ target } = {}) => {
    const dnsLib = require('dns').promises;
    const https  = require('https');

    const raw_t  = (target && target !== 'undefined') ? target : 'example.com';
    const domain = raw_t.replace(/^https?:\/\//, '').split('/')[0].toLowerCase().trim();
    const isIpInput = /^(\d{1,3}\.){3}\d{1,3}$/.test(domain) || /^[0-9a-f:]+$/i.test(domain) && domain.includes(':');

    // ── HTTPS GET helper ─────────────────────────────────────────
    function get(url, ms = 10000) {
      return new Promise((resolve, reject) => {
        const req = https.get(url, { timeout: ms, headers: { 'User-Agent': 'SecurityScanner/1.0' } }, res => {
          if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
            return get(res.headers.location, ms).then(resolve).catch(reject);
          }
          let buf = '';
          res.on('data', c => buf += c);
          res.on('end', () => resolve(buf));
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
      });
    }

    function postForm(url, body, ms = 15000) {
      return new Promise((resolve, reject) => {
        const parsed = new URL(url);
        const opts = {
          hostname: parsed.hostname,
          path: parsed.pathname + (parsed.search || ''),
          method: 'POST',
          timeout: ms,
          headers: {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(body)
          }
        };
        const req = https.request(opts, res => {
          let buf = '';
          res.on('data', c => buf += c);
          res.on('end', () => resolve(buf));
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('postForm timeout')); });
        req.write(body);
        req.end();
      });
    }

    // ── 1. Resolve IP ────────────────────────────────────────────
    let resolvedIp = null;
    try { resolvedIp = (await dnsLib.lookup(domain)).address; } catch {}

    // ── 2. Real DNS records (all record types in parallel) ───────
    const dig = { A: [], AAAA: [], MX: [], NS: [], TXT: [], SOA: [], CAA: [] };
    await Promise.allSettled([
      dnsLib.resolve4(domain).then(r  => { dig.A    = r; }).catch(() => {}),
      dnsLib.resolve6(domain).then(r  => { dig.AAAA = r; }).catch(() => {}),
      dnsLib.resolveMx(domain).then(r => {
        dig.MX = r.sort((a, b) => a.priority - b.priority).map(m => `${m.priority} ${m.exchange}`);
      }).catch(() => {}),
      dnsLib.resolveNs(domain).then(r => { dig.NS  = r.sort(); }).catch(() => {}),
      dnsLib.resolveTxt(domain).then(r=> { dig.TXT = r.map(a => a.join('')); }).catch(() => {}),
      dnsLib.resolveSoa(domain).then(r=> {
        dig.SOA = [`${r.nsname} ${r.hostmaster} ${r.serial} ${r.refresh} ${r.retry} ${r.expire} ${r.minttl}`];
      }).catch(() => {}),
      dnsLib.resolveCaa(domain).then(r=> {
        dig.CAA = r.map(c => {
          const tag = c.issue      !== undefined ? `issue "${c.issue}"` :
                      c.issuewild  !== undefined ? `issuewild "${c.issuewild}"` :
                      c.iodef      !== undefined ? `iodef "${c.iodef}"` : JSON.stringify(c);
          return `${c.critical} ${tag}`;
        });
      }).catch(() => {}),
    ]);

    // ── 3. Reverse IP — osint.sh (no rate limit) with HackerTarget fallback ──
    const reverseIp = { ip: resolvedIp, domains: [], error: null, source: 'osint.sh' };
    if (resolvedIp) {
      try {
        // POST to osint.sh/reverseip/ — returns server-rendered HTML table
        const osintHtml = await postForm('https://osint.sh/reverseip/', `domain=${encodeURIComponent(resolvedIp)}`);
        // Parse <td data-th="Domain">...</td> cells
        const domainMatches = osintHtml.match(/<td data-th="Domain">\s*([\w.\-]+)\s*<\/td>/gi) || [];
        const parsedDomains = domainMatches.map(m => {
          const inner = m.replace(/<[^>]+>/g, '').trim();
          return inner;
        }).filter(d => d.length > 0 && d.includes('.'));
        if (parsedDomains.length > 0) {
          reverseIp.domains = parsedDomains;
        } else {
          // osint.sh returned nothing or blocked — fallback to HackerTarget
          reverseIp.source = 'HackerTarget';
          const raw = await get(`https://api.hackertarget.com/reverseiplookup/?q=${resolvedIp}`);
          if (raw.includes('API count exceeded') || raw.includes('error detected')) {
            reverseIp.error = raw.trim();
          } else {
            reverseIp.domains = raw.trim().split('\n').map(s => s.trim()).filter(Boolean);
          }
        }
      } catch (e) {
        reverseIp.error = 'Lookup failed: ' + e.message;
        // Try HackerTarget as backup
        try {
          reverseIp.source = 'HackerTarget';
          const raw = await get(`https://api.hackertarget.com/reverseiplookup/?q=${resolvedIp}`);
          if (!raw.includes('API count exceeded') && !raw.includes('error detected')) {
            reverseIp.domains = raw.trim().split('\n').map(s => s.trim()).filter(Boolean);
            reverseIp.error = null;
          }
        } catch (_) {}
      }
    }

    // ── 4. Subdomains — multiple sources + DNS resolution ────────
    const subList = {};
    const sources = [];

    // HackerTarget hostsearch
    try {
      const raw = await get(`https://api.hackertarget.com/hostsearch/?q=${domain}`);
      if (raw && !raw.includes('error') && !raw.includes('API count') && raw.includes(',')) {
        for (const line of raw.trim().split('\n')) {
          const [sub, ip] = line.split(',');
          if (sub && sub.trim().includes('.') && sub.trim().endsWith(`.${domain}`)) {
            subList[sub.trim()] = { ip: ip?.trim() || null, source: 'HackerTarget' };
          }
        }
        if (Object.keys(subList).length) sources.push('HackerTarget');
      }
    } catch {}

    // crt.sh certificate transparency
    try {
      const raw   = await get(`https://crt.sh/?q=%25.${domain}&output=json`);
      const certs = JSON.parse(raw);
      let crtAdded = 0;
      for (const cert of certs) {
        for (let name of (cert.name_value || '').split('\n')) {
          name = name.trim().replace(/^\*\./, '').toLowerCase();
          if (name && name !== domain && name.endsWith(`.${domain}`) && !subList[name]) {
            subList[name] = { ip: null, source: 'crt.sh' };
            crtAdded++;
          }
        }
      }
      if (crtAdded) sources.push('crt.sh');
    } catch {}

    // AlienVault OTX passive DNS (no key needed for basic queries)
    try {
      const raw  = await get(`https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns`);
      const data = JSON.parse(raw);
      let otxAdded = 0;
      for (const rec of (data.passive_dns || [])) {
        const hostname = rec.hostname?.toLowerCase();
        if (hostname && hostname.endsWith(`.${domain}`) && !subList[hostname]) {
          subList[hostname] = { ip: rec.address || null, source: 'OTX' };
          otxAdded++;
        }
      }
      if (otxAdded) sources.push('OTX');
    } catch {}

    // MX record extraction — mail server hostnames that belong to this domain
    for (const mx of dig.MX) {
      const host = mx.replace(/^\d+\s+/, '').toLowerCase().replace(/\.$/, '');
      if (host.endsWith(`.${domain}`) && !subList[host]) {
        subList[host] = { ip: null, source: 'MX' };
      }
    }

    // NS record extraction — nameservers that belong to this domain
    for (const ns of dig.NS) {
      const host = ns.toLowerCase().replace(/\.$/, '');
      if (host.endsWith(`.${domain}`) && !subList[host]) {
        subList[host] = { ip: null, source: 'NS' };
      }
    }

    // Common subdomain brute-force — fast parallel DNS lookups
    const COMMON_NAMES = [
      'mail', 'mail2', 'smtp', 'smtps', 'imap', 'pop', 'pop3', 'webmail', 'autodiscover', 'autoconfig',
      'mx', 'mx1', 'mx2', 'exchange',
      'vpn', 'vpn2', 'remote', 'citrix', 'sslvpn', 'anyconnect',
      'ftp', 'sftp', 'files',
      'www', 'www2', 'web', 'portal', 'login', 'sso', 'auth',
      'api', 'api2', 'app', 'app2', 'apps',
      'admin', 'panel', 'manage', 'cp', 'cpanel', 'whm', 'plesk',
      'ns', 'ns1', 'ns2', 'ns3', 'dns', 'dns1', 'dns2',
      'dev', 'staging', 'test', 'uat', 'qa', 'beta', 'demo',
      'cloud', 'cdn', 'static', 'assets', 'media', 'img', 'images',
      'ssh', 'rdp', 'terminal',
      'git', 'gitlab', 'github', 'svn', 'jira', 'confluence',
      'shop', 'store', 'pay', 'billing', 'invoice',
      'blog', 'news', 'forum', 'community', 'help', 'support', 'kb',
      'db', 'mysql', 'sql', 'redis', 'elastic', 'kibana',
      'monitor', 'grafana', 'prometheus', 'zabbix', 'nagios',
      'wpad', 'proxy', 'gateway', 'fw', 'firewall',
    ];

    const bruteResults = await Promise.allSettled(
      COMMON_NAMES.filter(n => !subList[`${n}.${domain}`]).map(async name => {
        const fqdn = `${name}.${domain}`;
        try {
          const addr = (await dnsLib.lookup(fqdn)).address;
          return { fqdn, ip: addr };
        } catch { return null; }
      })
    );
    let bruteAdded = 0;
    for (const r of bruteResults) {
      if (r.status === 'fulfilled' && r.value) {
        subList[r.value.fqdn] = { ip: r.value.ip, source: 'DNS-brute' };
        bruteAdded++;
      }
    }
    if (bruteAdded) sources.push('DNS-brute');

    // DNS resolve IPs for any subdomain still missing one (batch, cap at 50)
    const unresolved = Object.keys(subList).filter(s => !subList[s].ip).slice(0, 50);
    if (unresolved.length) {
      await Promise.allSettled(unresolved.map(async sub => {
        try {
          const addr = (await dnsLib.lookup(sub)).address;
          subList[sub].ip = addr;
        } catch { subList[sub].ip = 'NXDOMAIN'; }
      }));
    }

    const subdomains = {
      count:  Object.keys(subList).length,
      source: sources.length ? sources.join(' + ') : 'crt.sh',
      list:   subList,
    };

    // ── 5. WHOIS via RDAP (rdap.org — free, JSON, no key) ────────
    let whoisData = null;
    try {
      const raw  = await get(`https://rdap.org/domain/${domain}`);
      const rdap = JSON.parse(raw);

      const getEvent  = (action) => {
        const ev = (rdap.events || []).find(e => e.eventAction === action);
        return ev ? ev.eventDate?.split('T')[0] : null;
      };
      const getEntity = (role) => (rdap.entities || []).find(e => (e.roles || []).includes(role));
      const getVcard  = (vc, type) => (vc?.[1] || []).find(v => v[0] === type)?.[3] ?? null;

      const registered = getEvent('registration');
      const updated    = getEvent('last changed');
      const expires    = getEvent('expiration');
      const daysLeft   = expires ? Math.floor((new Date(expires) - Date.now()) / 86400000) : null;

      const registrarEnt  = getEntity('registrar');
      const registrantEnt = getEntity('registrant');

      // Privacy service name patterns — many services have unique brand names
      const PRIVACY_RE = /redact|privacy|proxy|protect|masked|whoisguard|withheld|id.?shield|perfect.privacy|domainsbyproxy|domainprotect|contactprivacy|whoisprivacy|registrant.privacy|private.registrant|data.protected|gdpr|not\.disclosed|upon.request|registrar.abuse|data.redacted/i;

      let regInfo = null;
      if (registrantEnt) {
        // Some RDAP responses put actual data in nested entities under the registrant
        const vc = registrantEnt.vcardArray
          || (registrantEnt.entities || []).find(e => e.vcardArray)?.vcardArray;
        const adr = (vc?.[1] || []).find(v => v[0] === 'adr');
        const adrVal = adr?.[3];
        regInfo = {
          name:    getVcard(vc, 'fn'),
          org:     getVcard(vc, 'org'),
          email:   getVcard(vc, 'email'),
          phone:   getVcard(vc, 'tel'),
          street:  Array.isArray(adrVal) ? adrVal[2] : null,
          city:    Array.isArray(adrVal) ? adrVal[3] : null,
          state:   Array.isArray(adrVal) ? adrVal[4] : null,
          zip:     Array.isArray(adrVal) ? adrVal[5] : null,
          country: Array.isArray(adrVal) ? adrVal[6] : (typeof adrVal === 'string' ? adrVal : null),
        };
      }

      const isPrivacy = !regInfo?.name?.trim()
        || PRIVACY_RE.test(regInfo.name)
        || PRIVACY_RE.test(regInfo.email || '')
        || PRIVACY_RE.test(regInfo.org || '');

      whoisData = {
        registrar:         getVcard(registrarEnt?.vcardArray, 'fn') || 'Unknown',
        registered,
        updated,
        expires,
        days_until_expiry: daysLeft,
        status:            rdap.status || [],
        nameservers:       (rdap.nameservers || []).map(ns => (ns.ldhName || '').toLowerCase()).filter(Boolean),
        dnssec:            rdap.secureDNS?.delegationSigned ? 'signed' : 'unsigned',
        privacy:           isPrivacy,
        registrant:        regInfo,
      };
    } catch (e) {
      whoisData = { error: 'WHOIS lookup failed — ' + e.message };
    }

    // ── 6. Build findings from real data ─────────────────────────
    const findings = [];
    if (reverseIp.domains.length > 1) {
      findings.push({ type: 'reverse_ip', detail: `${reverseIp.domains.length} domains share this IP — shared hosting`, severity: 'info' });
    }
    if (subdomains.count > 0) {
      findings.push({ type: 'subdomains', detail: `${subdomains.count} subdomain(s) discovered`, severity: 'info' });
    }
    const hasSPF   = dig.TXT.some(t => t.startsWith('v=spf1'));
    const hasDMARC = dig.TXT.some(t => /^v=dmarc1/i.test(t));
    if (!hasSPF)   findings.push({ type: 'dns', detail: 'No SPF record — domain is spoofable via email', severity: 'medium' });
    if (!hasDMARC) findings.push({ type: 'dns', detail: 'No DMARC record — email abuse not monitored',    severity: 'medium' });
    if (hasSPF)    findings.push({ type: 'dns', detail: 'SPF: ' + dig.TXT.find(t => t.startsWith('v=spf1')), severity: 'info' });
    if (hasDMARC)  findings.push({ type: 'dns', detail: 'DMARC: ' + dig.TXT.find(t => /^v=dmarc1/i.test(t)), severity: 'info' });
    if (whoisData && !whoisData.error) {
      if (whoisData.dnssec === 'unsigned') {
        findings.push({ type: 'whois', detail: 'DNSSEC unsigned — DNS responses not cryptographically signed', severity: 'low' });
      }
      if (whoisData.days_until_expiry !== null && whoisData.days_until_expiry < 30) {
        findings.push({ type: 'whois', detail: `Domain expires in ${whoisData.days_until_expiry} days — renewal urgent`, severity: 'high' });
      } else if (whoisData.days_until_expiry !== null && whoisData.days_until_expiry < 90) {
        findings.push({ type: 'whois', detail: `Domain expires in ${whoisData.days_until_expiry} days`, severity: 'medium' });
      }
    }

    // DNS records in the format the renderer expects
    const dnsRecords = [
      ...dig.A.map(ip  => ({ type: 'A',    host: domain, ip })),
      ...dig.AAAA.map(ip => ({ type: 'AAAA', host: domain, ip })),
      ...dig.MX.map(t  => ({ type: 'MX',   host: domain, target: t })),
      ...dig.NS.map(t  => ({ type: 'NS',   host: domain, target: t })),
      ...dig.TXT.map(t => ({ type: 'TXT',  host: domain, txt: t })),
    ];

    return {
      target: domain,
      is_ip:       isIpInput,
      resolved_ip: resolvedIp || 'Could not resolve',
      findings,
      reverse_ip:  reverseIp,
      subdomains,
      dns:         dnsRecords,
      dig,
      whois:       whoisData,
      shodan:      null,
    };
  },

  'inspect.php': async ({ url } = {}) => {
    if (!url || url === 'undefined') return { error: 'No URL provided' };
    const domain = (() => { try { return new URL(url).hostname; } catch { return url; } })();

    // Fetch the target page
    let resp;
    try { resp = await httpGet(url, { timeout: 12000 }); }
    catch (e) { return { error: `Could not fetch ${url}: ${e.message}` }; }

    const { status, headers: rh, body: html, finalUrl } = resp;

    // ── Header security analysis ──────────────────────────────
    const REQ_HDRS = {
      'strict-transport-security': { msg: 'HSTS not set — cleartext downgrade possible',  severity: 'high'   },
      'x-frame-options':           { msg: 'Clickjacking protection missing',               severity: 'medium' },
      'x-content-type-options':    { msg: 'MIME-sniffing not prevented',                  severity: 'low'    },
      'content-security-policy':   { msg: 'No CSP — XSS protection limited',              severity: 'medium' },
      'referrer-policy':           { msg: 'Referrer-Policy not set',                      severity: 'low'    },
    };
    const LEAK_HDRS = {
      'server':           { msg: 'Reveals web server software and version', severity: 'low' },
      'x-powered-by':     { msg: 'Reveals server-side technology version',  severity: 'low' },
      'x-aspnet-version': { msg: 'Reveals ASP.NET version',                severity: 'low' },
      'x-generator':      { msg: 'Reveals CMS/generator version',          severity: 'low' },
    };
    const header_issues = [];
    for (const [h, info] of Object.entries(REQ_HDRS)) {
      if (!rh[h]) header_issues.push({ header: h, value: null, severity: info.severity, msg: 'MISSING: ' + info.msg });
    }
    for (const [h, info] of Object.entries(LEAK_HDRS)) {
      if (rh[h]) header_issues.push({ header: h, value: Array.isArray(rh[h]) ? rh[h].join(', ') : rh[h], severity: info.severity, msg: info.msg });
    }

    // ── Cookie analysis ───────────────────────────────────────
    const rawCookies = Array.isArray(rh['set-cookie']) ? rh['set-cookie'] : rh['set-cookie'] ? [rh['set-cookie']] : [];
    const cookies = rawCookies.map(raw => {
      const parts = raw.split(';').map(p => p.trim());
      const name  = parts[0].split('=')[0];
      const attrs = parts.slice(1).map(p => p.toLowerCase());
      const sensitive = /sess|auth|token|login|user|jwt|sid/i.test(name);
      const httponly  = attrs.some(a => a === 'httponly');
      const secure    = attrs.some(a => a === 'secure');
      const samesite  = (attrs.find(a => a.startsWith('samesite=')) || '').split('=')[1] || null;
      return {
        name, httponly, secure, samesite, sensitive,
        issues: [
          !httponly ? 'Missing HttpOnly — readable by JavaScript (XSS risk)' : null,
          !secure   ? 'Missing Secure — may be sent over HTTP'               : null,
          !samesite ? 'Missing SameSite — CSRF risk'                         : null,
        ].filter(Boolean),
      };
    });

    // ── CORS ─────────────────────────────────────────────────
    const corsOrigin = rh['access-control-allow-origin'] || null;
    let cors = null;
    if (corsOrigin) {
      const corsIssues = corsOrigin === '*' ? ['Wildcard ACAO — any origin can read responses'] : [];
      cors = { origin: corsOrigin, credentials: rh['access-control-allow-credentials'] || null, methods: rh['access-control-allow-methods'] || null, allow_headers: rh['access-control-allow-headers'] || null, issues: corsIssues };
    }

    // ── HTML scanning ─────────────────────────────────────────
    const emails   = [...new Set((html.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g) || []))].slice(0, 20);
    const comments = (html.match(/<!--[\s\S]*?-->/g) || []).filter(c => /password|todo|debug|fixme|token|secret|api|key|remove|temp/i.test(c)).map(c => ({ text: c.slice(0, 300), source: url }));

    // SRI check for external scripts/styles
    const sri_missing = [];
    for (const tag of (html.match(/<script[^>]+src=["'][^"']+["'][^>]*>/gi) || [])) {
      const src = tag.match(/src=["']([^"']+)['"]/)?.[1];
      if (!src) continue;
      try { const u = new URL(src, url); if (u.hostname !== domain && !tag.includes('integrity=')) sri_missing.push({ type: 'script', host: u.hostname, url: u.href }); } catch {}
    }
    for (const tag of (html.match(/<link[^>]+href=["'][^"']*\.css[^"']*["'][^>]*>/gi) || [])) {
      const href = tag.match(/href=["']([^"']+)['"]/)?.[1];
      if (!href) continue;
      try { const u = new URL(href, url); if (u.hostname !== domain && !tag.includes('integrity=')) sri_missing.push({ type: 'stylesheet', host: u.hostname, url: u.href }); } catch {}
    }

    // Mixed content
    const mixed_content = [];
    if (url.startsWith('https:')) {
      const mre = /(?:src|href|action)=["'](http:\/\/[^"']+)['"]/gi;
      let mm;
      while ((mm = mre.exec(html)) !== null && mixed_content.length < 10) {
        mixed_content.push({ type: mm[0].split('=')[0].replace(/[<\s]/g,''), url: mm[1], active: /src=["']http:/i.test(mm[0]), tag: mm[0] });
      }
    }

    // Find linked JS files
    const jsUrls = [...new Set((html.match(/src=["']([^"']*\.js(?:\?[^"']*)?)['"]/g) || [])
      .map(m => m.match(/src=["']([^"']+)['"]/)[1])
      .map(src => { try { return new URL(src, url).href; } catch { return null; } })
      .filter(u => u?.startsWith('http'))
    )].slice(0, 6);

    // Secret patterns — scanned against full JS file
    const SECRET_PATTERNS = [
      { re: /(AIza[0-9A-Za-z\-_]{35})/g,                                                 type: 'Google API Key',      severity: 'critical' },
      { re: /(sk_live_[0-9a-zA-Z]{24,})/g,                                               type: 'Stripe Secret Key',   severity: 'critical' },
      { re: /(rk_live_[0-9a-zA-Z]{24,})/g,                                               type: 'Stripe Restricted Key',severity:'critical' },
      { re: /(AKIA[0-9A-Z]{16})/g,                                                        type: 'AWS Access Key',      severity: 'critical' },
      { re: /(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{6,})["']/gi,                    type: 'Hardcoded Password',  severity: 'critical' },
      { re: /(?:api[_\-]?key|apikey)\s*[:=]\s*["']([^"']{8,})["']/gi,                   type: 'API Key',             severity: 'critical' },
      { re: /eyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}/g,       type: 'JWT Token',           severity: 'high'     },
      { re: /(?:secret|token|auth_token)\s*[:=]\s*["']([^"']{8,})["']/gi,                type: 'Secret/Token',        severity: 'high'     },
      { re: /(?:db_pass|database_password|db_password)\s*[:=]\s*["']([^"']{4,})["']/gi, type: 'Database Password',   severity: 'critical' },
      { re: /(?:private[_\-]?key)\s*[:=]\s*["']([^"']{12,})["']/gi,                     type: 'Private Key',         severity: 'critical' },
    ];
    // Hash patterns — context-aware (variable name must suggest a hash)
    const HASH_PATTERNS = [
      { re: /(?:hash|md5|sha1?|password_hash|pw_hash|stored_hash)\s*[:=]\s*["']([a-f0-9]{32})["']/gi, type: 'MD5 hash (32-char hex)',    severity: 'high'     },
      { re: /(?:hash|sha1|sha_hash)\s*[:=]\s*["']([a-f0-9]{40})["']/gi,                               type: 'SHA-1 hash (40-char hex)',  severity: 'high'     },
      { re: /(?:hash|sha256|sha_256|sha2)\s*[:=]\s*["']([a-f0-9]{64})["']/gi,                         type: 'SHA-256 hash (64-char hex)',severity: 'high'     },
      { re: /(\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53})/g,                                                  type: 'bcrypt hash',               severity: 'critical' },
      { re: /(\$argon2[id]\$[^\s"'<>]{20,})/g,                                                         type: 'Argon2 hash',               severity: 'critical' },
    ];
    const DOM_XSS = [
      { re: /\.innerHTML\s*=/g,         sink: 'innerHTML assignment'            },
      { re: /\.outerHTML\s*=/g,         sink: 'outerHTML assignment'            },
      { re: /document\.write\s*\(/g,    sink: 'document.write'                  },
      { re: /\beval\s*\(/g,             sink: 'eval() call'                     },
      { re: /location\.href\s*=/g,      sink: 'location.href assign'            },
      { re: /setTimeout\s*\(\s*["'`]/g, sink: 'setTimeout with string (eval-like)' },
    ];

    const credentials = [], dom_xss = [], api_endpoints = [], js_files = [];
    const hardcoded_hashes = [], encoded_strings = [];

    // Helper: add API endpoint — deduplicates by resolved URL, skips templates
    const addEndpoint = (ep, src, lineNum, method, ctx) => {
      if (!ep || ep.length < 3 || /[{*<>]|\.\.\.|undefined|null|NaN/.test(ep)) return;
      try {
        const resolved = /^https?:\/\//.test(ep) ? ep : new URL(ep, url).href;
        if (api_endpoints.some(e => e.resolved === resolved)) return;
        api_endpoints.push({ url: ep, resolved, source: src, line: lineNum, method: (method||'?').slice(0,6), context: (ctx||'').slice(0, 140) });
      } catch {}
    };

    // Scan HTML for form actions and data attributes
    const formActRe = /<form[^>]+action=["']([^"']{3,})["'][^>]*>/gi;
    let fam; while ((fam = formActRe.exec(html)) !== null) addEndpoint(fam[1], url, null, 'POST', fam[0].slice(0, 100));
    const dataAttrRe = /data-(?:url|endpoint|href|src|action)=["']([^"']{4,})["']/gi;
    let dam; while ((dam = dataAttrRe.exec(html)) !== null) {
      if (/\/api\/|\/v\d+\/|graphql|\/rest\//.test(dam[1])) addEndpoint(dam[1], url, null, '?', dam[0].slice(0, 100));
    }

    const jsResults = await Promise.allSettled(jsUrls.map(async jsUrl => {
      try { const r = await httpGet(jsUrl, { timeout: 8000 }); return { url: jsUrl, size: r.body.length, body: r.body }; }
      catch { return { url: jsUrl, size: 0, body: '' }; }
    }));

    // Extract inline <script> blocks from HTML and treat as a virtual JS file
    const inlineBody = (html.match(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi) || [])
      .map(s => s.replace(/<\/?script[^>]*>/gi, ''))
      .filter(s => s.trim().length > 20)
      .join('\n');
    const allJsEntries = [
      ...jsResults.filter(r => r.value).map(r => r.value),
      ...(inlineBody.trim() ? [{ url: url + ' [inline script]', size: inlineBody.length, body: inlineBody }] : []),
    ];

    for (const { url: jsUrl, size, body: js } of allJsEntries) {
      let fc = 0;

      // Full-file secret scan (finds ALL occurrences, not just first)
      for (const pat of SECRET_PATTERNS) {
        pat.re.lastIndex = 0;
        let m;
        while ((m = pat.re.exec(js)) !== null) {
          const raw = m[1] || m[0];
          const lineNum = js.slice(0, m.index).split('\n').length;
          credentials.push({ type: pat.type, value: raw, source: jsUrl, line: lineNum, severity: pat.severity });
          fc++;
        }
      }

      // Line-by-line scan
      const lines = js.split('\n');
      for (const [i, line] of lines.entries()) {
        // DOM XSS sinks
        for (const { re, sink } of DOM_XSS) {
          re.lastIndex = 0;
          if (re.test(line)) { dom_xss.push({ sink, line: i+1, context: line.trim().slice(0,120), source: jsUrl }); fc++; break; }
        }

        // Specific patterns first (so method is captured accurately before dedup kicks in)

        // fetch() calls — default method GET
        const FETCH_RE = /\bfetch\s*\(\s*["'`]([^"'`]{3,})["'`]/g;
        let fem; while ((fem = FETCH_RE.exec(line)) !== null) addEndpoint(fem[1], jsUrl, i+1, 'GET', line.trim());

        // axios.method() calls
        const AXIOS_RE = /\baxios\.(\w+)\s*\(\s*["'`]([^"'`]{3,})["'`]/g;
        let axm; while ((axm = AXIOS_RE.exec(line)) !== null) addEndpoint(axm[2], jsUrl, i+1, axm[1].toUpperCase().slice(0,6), line.trim());

        // XMLHttpRequest open(method, url)
        const XHR_RE = /\.open\s*\(\s*["'`](\w+)["'`]\s*,\s*["'`]([^"'`]{3,})["'`]/g;
        let xhm; while ((xhm = XHR_RE.exec(line)) !== null) addEndpoint(xhm[2], jsUrl, i+1, xhm[1].toUpperCase(), line.trim());

        // url / endpoint variable assignments
        const URL_VAR_RE = /(?:url|endpoint|baseUrl|apiUrl|restUrl|apiEndpoint)\s*[:=]\s*["'`]([^"'`\s]{5,})["'`]/gi;
        let uvm; while ((uvm = URL_VAR_RE.exec(line)) !== null) addEndpoint(uvm[1], jsUrl, i+1, '?', line.trim());

        // External full URLs (different domain)
        const EXT_RE = /["'`](https?:\/\/[^"'`\s<>]{10,120})["'`]/g;
        let eum; while ((eum = EXT_RE.exec(line)) !== null) {
          try { if (new URL(eum[1]).hostname !== domain) addEndpoint(eum[1], jsUrl, i+1, '?', line.trim()); } catch {}
        }

        // Generic API path literals — fallback only (dedup means these only add paths missed above)
        const API_PATH_RE = /["'`](\/(?:api|v\d+(?:\.\d+)?|graphql|rest|gql|rpc|endpoint|service|query|data|search|auth)[^"'`\s<>]{1,120})["'`]/g;
        let apm; while ((apm = API_PATH_RE.exec(line)) !== null) addEndpoint(apm[1], jsUrl, i+1, '?', line.trim());

        // Hardcoded hash detection
        for (const { re, type, severity } of HASH_PATTERNS) {
          re.lastIndex = 0;
          const hm = re.exec(line);
          if (hm) { hardcoded_hashes.push({ type, value: hm[1]||hm[0], source: jsUrl, line: i+1, context: line.trim().slice(0,120), severity }); fc++; }
        }

        // Base64 encoded strings — detect, decode, flag if readable
        const B64_RE = /["'`]([A-Za-z0-9+/]{16,}={0,2})["'`]/g;
        let bm;
        while ((bm = B64_RE.exec(line)) !== null) {
          const raw = bm[1];
          try {
            const decoded = Buffer.from(raw, 'base64').toString('utf8');
            const printable = decoded.split('').filter(c => c.charCodeAt(0) >= 0x20 && c.charCodeAt(0) < 0x7F).length;
            // Must be >85% printable, ≥8 chars, not just a word
            if (printable / decoded.length > 0.85 && decoded.length >= 8 && !/^[a-zA-Z]{6,}$/.test(decoded)) {
              const credCtx = /password|passwd|secret|key|token|auth|credential|user/i.test(decoded + line);
              if (!encoded_strings.some(e => e.raw === raw.slice(0,60))) {
                encoded_strings.push({ type: 'Base64', raw: raw.slice(0,60)+(raw.length>60?'…':''), decoded: decoded.slice(0,300), source: jsUrl, line: i+1, severity: credCtx ? 'critical' : 'medium' });
                if (credCtx) fc++;
              }
            }
          } catch {}
        }
      }
      js_files.push({ url: jsUrl, size, findings_count: fc, inline: jsUrl.includes('[inline') });
    }

    // localStorage / postMessage scan across all content
    const allContent = html + jsResults.map(r => r.value?.body || '').join('\n');
    const localstorage = [];
    const lsRe = /(localStorage|sessionStorage)\.setItem\s*\(\s*["']([^"']+)["']/g;
    let lm;
    while ((lm = lsRe.exec(allContent)) !== null) {
      if (/token|auth|pass|secret|key|jwt|session/i.test(lm[2])) {
        localstorage.push({ storage: lm[1], key: lm[2], source: url, context: lm[0] });
      }
    }
    const postmessage = [];
    if (/addEventListener\s*\(\s*["']message["']/.test(allContent)) {
      postmessage.push({ has_origin_check: /event\.origin|e\.origin/.test(allContent), source: url, context: "addEventListener('message', ...)" });
    }

    // Build consolidated findings
    const findings = [
      ...header_issues.map(h => ({ type: h.value ? 'header' : 'header_missing', detail: h.value ? `Response header [${h.header}: ${h.value}] — ${h.msg}` : `Missing header [${h.header}] — ${h.msg}`, severity: h.severity })),
      ...cookies.filter(c => c.issues.length).flatMap(c => c.issues.map(i => ({ type: 'cookie', detail: `Cookie [${c.name}] — ${i}`, severity: c.sensitive ? 'medium' : 'low' }))),
      ...credentials.map(c => ({ type: 'credential', detail: `${c.type} found in ${c.source.split('/').pop()} line ${c.line||'?'}: "${c.value.slice(0,80)}"`, severity: c.severity || 'critical' })),
      ...hardcoded_hashes.map(h => ({ type: 'hardcoded_hash', detail: `${h.type} in ${h.source} line ${h.line}: ${h.value.slice(0,20)}…`, severity: h.severity })),
      ...encoded_strings.filter(e => e.severity === 'critical').map(e => ({ type: 'encoded_string', detail: `Base64 credential candidate in ${e.source} line ${e.line} — decoded: ${e.decoded.slice(0,60)}`, severity: 'critical' })),
      ...dom_xss.slice(0,8).map(x => ({ type: 'dom_xss', detail: `DOM XSS sink [${x.sink}] line ${x.line}: ${x.context.slice(0,80)}`, severity: 'medium', url: x.source })),
      ...sri_missing.slice(0,5).map(s => ({ type: 'sri', detail: `No integrity= on external ${s.type} from ${s.host}`, severity: 'medium' })),
      ...mixed_content.map(m => ({ type: 'mixed_content', detail: `Mixed content [${m.type}] — ${m.url}`, severity: m.active ? 'high' : 'medium' })),
      ...(cors?.issues||[]).map(i => ({ type: 'cors', detail: i, severity: 'high' })),
      ...localstorage.map(l => ({ type: 'localstorage', detail: `Sensitive key '${l.key}' in ${l.storage}`, severity: 'medium' })),
      ...postmessage.filter(p => !p.has_origin_check).map(() => ({ type: 'postmessage', detail: 'postMessage listener missing origin check', severity: 'medium' })),
      ...comments.slice(0,5).map(c => ({ type: 'comment', detail: `Sensitive HTML comment: ${c.text.slice(0,120)}`, severity: 'medium' })),
    ];

    const SEV = { critical:4, high:3, medium:2, low:1, info:0 };
    const maxSev = findings.reduce((m,f) => Math.max(m, SEV[f.severity]||0), 0);
    const severity = Object.keys(SEV).find(k => SEV[k] === maxSev) || 'info';

    return {
      url, domain,
      http_code: status, final_url: finalUrl || url,
      content_type: rh['content-type'] || null,
      severity, findings,
      headers:      rh,
      header_issues,
      cors,
      cookies,
      credentials,
      api_endpoints:    api_endpoints.slice(0, 50),
      hardcoded_hashes: hardcoded_hashes.slice(0, 30),
      encoded_strings:  encoded_strings.slice(0, 30),
      js_files,
      dom_xss,
      sri_missing:      sri_missing.slice(0,10),
      mixed_content,
      localstorage,
      postmessage,
      comments,
      emails:           emails.map(e => ({ email: e, source: url })),
      source_maps:      [],
      outdated_libs:    [],
      insecure_forms:   [],
      autocomplete:     [],
      cache_issues:     [],
      http_methods:     null,
      backup_links:     [],
      internal_hosts:   [],
      internal_ips:     [],
      url_param_leaks:  [],
      error_disclosures:[],
    };
  },

  'crawl.php': async ({ url, mode } = {}) => {
    if (!url || url === 'undefined') return { error: 'No URL provided' };
    const base = url.replace(/\/$/, '');

    // ── Sensitive path probe list ─────────────────────────────
    const PROBE_PATHS = [
      // Secrets / config
      { path: '/.env',                   severity: 'critical', reason: 'Environment file — may contain DB credentials, API keys' },
      { path: '/.env.local',             severity: 'critical', reason: 'Local env override file' },
      { path: '/.env.backup',            severity: 'critical', reason: 'Env backup file' },
      { path: '/.env.production',        severity: 'critical', reason: 'Production env file' },
      { path: '/.git/config',            severity: 'critical', reason: 'Git config exposed — source code may be downloadable' },
      { path: '/.git/HEAD',              severity: 'critical', reason: 'Git HEAD ref exposed' },
      { path: '/.gitignore',             severity: 'low',      reason: 'Project structure enumeration' },
      { path: '/config.php',             severity: 'high',     reason: 'PHP config file may be world-readable' },
      { path: '/config.yml',             severity: 'high',     reason: 'YAML config file exposed' },
      { path: '/config.json',            severity: 'high',     reason: 'JSON config exposed' },
      { path: '/database.yml',           severity: 'high',     reason: 'Database credentials (Rails)' },
      { path: '/wp-config.php.bak',      severity: 'critical', reason: 'WordPress config backup with credentials' },
      // WordPress
      { path: '/wp-login.php',           severity: 'medium',   reason: 'WordPress login — brute-forceable' },
      { path: '/wp-admin/',              severity: 'medium',   reason: 'WordPress admin panel' },
      { path: '/xmlrpc.php',             severity: 'high',     reason: 'XML-RPC enabled — brute-force and SSRF vector' },
      { path: '/wp-json/wp/v2/users',    severity: 'medium',   reason: 'WordPress REST API user enumeration' },
      { path: '/wp-content/debug.log',   severity: 'high',     reason: 'WordPress debug log may contain stack traces and paths' },
      { path: '/wp-includes/version.php',severity: 'low',      reason: 'WordPress version disclosure' },
      // Admin panels
      { path: '/phpmyadmin/',            severity: 'critical', reason: 'phpMyAdmin exposed — database admin interface' },
      { path: '/phpmyadmin/index.php',   severity: 'critical', reason: 'phpMyAdmin index' },
      { path: '/adminer.php',            severity: 'critical', reason: 'Adminer DB tool exposed' },
      { path: '/admin/',                 severity: 'high',     reason: 'Admin panel publicly accessible' },
      { path: '/admin/login',            severity: 'high',     reason: 'Admin login page' },
      { path: '/administrator/',         severity: 'high',     reason: 'Joomla-style admin panel' },
      { path: '/cpanel',                 severity: 'high',     reason: 'cPanel exposed' },
      // Dumps / backups
      { path: '/backup/',                severity: 'critical', reason: 'Backup directory exposed' },
      { path: '/backup.zip',             severity: 'critical', reason: 'Site backup archive' },
      { path: '/backup.sql',             severity: 'critical', reason: 'Database dump exposed' },
      { path: '/db.sql',                 severity: 'critical', reason: 'Database dump' },
      { path: '/dump.sql',               severity: 'critical', reason: 'Database dump' },
      { path: '/database.sql',           severity: 'critical', reason: 'Database dump' },
      { path: '/.DS_Store',              severity: 'medium',   reason: 'macOS metadata — leaks directory structure' },
      // Info pages
      { path: '/phpinfo.php',            severity: 'high',     reason: 'phpinfo() exposes full server configuration' },
      { path: '/info.php',               severity: 'high',     reason: 'phpinfo() shorthand' },
      { path: '/test.php',               severity: 'medium',   reason: 'Test file left on server' },
      { path: '/robots.txt',             severity: 'info',     reason: 'Review for hidden paths / Disallow entries' },
      { path: '/sitemap.xml',            severity: 'info',     reason: 'Full URL map of the site' },
      { path: '/.well-known/security.txt', severity: 'info',  reason: 'Security contact policy' },
      // Error / logs
      { path: '/error_log',              severity: 'high',     reason: 'PHP error log exposed — paths and exceptions visible' },
      { path: '/error.log',              severity: 'high',     reason: 'Server error log' },
      { path: '/debug.log',              severity: 'high',     reason: 'Application debug log' },
      { path: '/access.log',             severity: 'high',     reason: 'HTTP access log — IP and request history' },
      // Panels / monitoring
      { path: '/.well-known/acme-challenge/', severity: 'info', reason: 'ACME challenge directory' },
      { path: '/server-status',          severity: 'high',     reason: 'Apache server-status — exposes active connections and IPs' },
      { path: '/server-info',            severity: 'high',     reason: 'Apache server-info — module/config disclosure' },
      { path: '/_profiler',             severity: 'high',      reason: 'Symfony profiler — full request/response debug info' },
      { path: '/.htaccess',              severity: 'medium',   reason: '.htaccess exposed — security rule disclosure' },
    ];

    // ── Classify a real HTTP response ─────────────────────────
    function classify(path, code, body, headers, cfg) {
      if (code === 0) return null;
      const ct = (headers['content-type'] || '').toLowerCase();
      const isHtml = ct.includes('text/html');
      // Skip if redirected to homepage (false positive)
      const cl = parseInt(headers['content-length'] || '0', 10);

      if (code === 404 || code === 410) return null;

      // 200 on sensitive paths is highest signal
      if (code === 200) {
        // Check body for phpinfo signature
        if (/phpinfo\(\)|PHP Version|php_uname/i.test(body?.slice(0, 4000) || '')) {
          return { ...cfg, severity: 'critical', reason: 'phpinfo() output confirmed — full server config exposed' };
        }
        // Check body confirms env file
        if (path.endsWith('.env') || path.endsWith('.env.local')) {
          if (/[A-Z_]+=/.test(body?.slice(0, 2000) || '')) {
            return { ...cfg, severity: 'critical', reason: cfg.reason + ' (content confirmed)' };
          }
        }
        if (path === '/robots.txt' || path === '/sitemap.xml' || path === '/.well-known/security.txt') {
          return { ...cfg, code, severity: 'info' };
        }
        return { ...cfg, code };
      }
      // 403 on sensitive paths = file exists, just blocked
      if (code === 403 && cfg.severity !== 'info') {
        return { ...cfg, code, severity: cfg.severity === 'critical' ? 'high' : cfg.severity, reason: cfg.reason + ' (access blocked — file exists)' };
      }
      // 301/302 redirect from admin panels
      if ((code === 301 || code === 302) && (path.includes('admin') || path.includes('wp-'))) {
        return { ...cfg, code, severity: 'low', reason: cfg.reason + ' (redirects — login wall)' };
      }
      // 405 on xmlrpc = enabled
      if (code === 405 && path.includes('xmlrpc')) {
        return { ...cfg, code, severity: 'high', reason: 'XML-RPC enabled (405 Method Not Allowed confirms endpoint active)' };
      }
      return null;
    }

    // ── Probe all paths in parallel (8 concurrent) ────────────
    const CONCURRENCY = 8;
    const probed = [];
    const findings = [];

    const chunks = [];
    for (let i = 0; i < PROBE_PATHS.length; i += CONCURRENCY) chunks.push(PROBE_PATHS.slice(i, i + CONCURRENCY));

    for (const chunk of chunks) {
      await Promise.allSettled(chunk.map(async cfg => {
        const probeUrl = base + cfg.path;
        let code = 0, body = '', headers = {};
        try {
          const r = await httpGet(probeUrl, { timeout: 7000, maxRedirects: 0 });
          code = r.status; body = r.body?.slice(0, 8000) || ''; headers = r.headers || {};
        } catch {}
        const entry = { url: probeUrl, path: cfg.path, code, reason: cfg.reason };
        probed.push(entry);
        const finding = classify(cfg.path, code, body, headers, cfg);
        if (finding) {
          findings.push({
            type: 'probe',
            detail: `${cfg.path} → HTTP ${code} — ${finding.reason}`,
            severity: finding.severity,
            url: probeUrl,
          });
        }
      }));
    }

    // ── Optional surface crawl ────────────────────────────────
    const crawled = [];
    if (mode === 'crawl') {
      try {
        const root = await httpGet(base + '/', { timeout: 10000 });
        crawled.push({ url: base + '/', code: root.status, type: root.headers['content-type'] || '', depth: 0 });
        const seen = new Set([base + '/']);
        const linkRe = /href=["']([^"'#?]+)["']/g;
        let lm;
        while ((lm = linkRe.exec(root.body || '')) !== null && crawled.length < 30) {
          try {
            const resolved = new URL(lm[1], base + '/').href;
            if (!resolved.startsWith(base) || seen.has(resolved)) continue;
            seen.add(resolved);
            const r2 = await httpGet(resolved, { timeout: 6000, maxRedirects: 2 });
            crawled.push({ url: resolved, code: r2.status, type: r2.headers['content-type'] || '', depth: 1 });
          } catch {}
        }
      } catch {}
    }

    // Stats
    const stats = {
      total:     probed.length,
      ok:        probed.filter(p => p.code === 200).length,
      redirect:  probed.filter(p => p.code === 301 || p.code === 302).length,
      forbidden: probed.filter(p => p.code === 403).length,
      not_found: probed.filter(p => p.code === 404 || p.code === 410).length,
      error:     probed.filter(p => p.code === 0).length,
    };

    // Pull robots.txt Disallow entries as extra info
    const robotsEntry = probed.find(p => p.path === '/robots.txt' && p.code === 200);
    const robotsDisallow = [];
    if (robotsEntry) {
      try {
        const r = await httpGet(base + '/robots.txt', { timeout: 5000 });
        for (const m of (r.body || '').matchAll(/^Disallow:\s*(.+)$/gm)) robotsDisallow.push(m[1].trim());
      } catch {}
    }

    return {
      target: base, base,
      stats, findings, probed, crawled,
      robots_disallow: robotsDisallow,
      endpoints: crawled.map(c => c.url),
    };
  },
};

// ── Serve a static file ───────────────────────────────────────
function serveStatic(res, filePath) {
  if (!fs.existsSync(filePath)) { res.writeHead(404); res.end('Not found'); return; }
  const ext  = path.extname(filePath);
  const mime = MIME[ext] || 'application/octet-stream';
  res.writeHead(200, { 'Content-Type': mime });
  res.end(fs.readFileSync(filePath));
}

// ── Render index.php with ROUTES injected ────────────────────
function renderIndex(sess, loginError = '', res) {
  let html = fs.readFileSync(path.join(WEBROOT, 'index.php'), 'utf8');
  if (sess) {
    const dashStart = html.indexOf('<!-- ─────────────────── DASHBOARD');
    html = html.substring(0, html.indexOf('<?php if (!$authenticated): ?>')) +
           html.substring(dashStart);
    html = html.replace(/<\?php[\s\S]*?\?>/g, '');
    // Inject CSRF into all hidden inputs
    html = html.replace(/name="csrf" value="[^"]*"/g, `name="csrf" value="${sess.csrf}"`);
    // Inject window.ROUTES — replaces the PHP block that was stripped
    const routesScript = `<script>\nwindow.ROUTES = ${JSON.stringify(sess.routes)};\n</script>`;
    html = html.replace('</head>', `${routesScript}\n</head>`);
  } else {
    html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Security Scanner</title><link rel="stylesheet" href="/assets/css/app.css"></head><body>
<div class="login-wrap"><div class="login-box">
  <div class="login-logo"><svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#00ff88" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg><span>Security Scanner</span></div>
  ${loginError ? `<div class="alert alert-danger">${loginError}</div>` : ''}
  <form method="POST" action="/login">
    <label>Email <span style="color:var(--muted);font-size:11px">(dev: any@email.com)</span></label>
    <input type="email" name="email" autofocus required placeholder="your@email.com">
    <label>Password <span style="color:var(--muted);font-size:11px">(dev: scanner123)</span></label>
    <input type="password" name="password" required placeholder="Enter scanner password">
    <button type="submit">Unlock</button>
  </form>
</div></div>
<script src="/assets/js/app.js"></script></body></html>`;
  }
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(html);
}

// ── Main request handler ──────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const url     = new URL(req.url, `http://localhost:${PORT}`);
  const urlPath = url.pathname;
  const sess    = getSession(req);

  console.log(`${req.method} ${urlPath}`);

  // Static assets — no auth required
  if (urlPath.startsWith('/assets/')) {
    return serveStatic(res, path.join(WEBROOT, urlPath));
  }

  // Login — accept any email in dev, check password only
  if (urlPath === '/login' && req.method === 'POST') {
    const body = await parseBody(req);
    if (body.password === DEV_PASSWORD) {
      const { id, routes } = makeSession();
      console.log('  New session routes:', routes);
      res.writeHead(302, {
        'Set-Cookie': `_s=${id}; HttpOnly; SameSite=Strict; Path=/`,
        'Location': '/',
      });
      return res.end();
    }
    return renderIndex(null, 'Invalid credentials', res);
  }

  // Logout — destroy session token
  if (urlPath === '/logout' || (urlPath === '/' && url.searchParams.has('logout'))) {
    const cookies = Object.fromEntries(
      (req.headers.cookie || '').split(';').map(c => c.trim().split('=').map(decodeURIComponent))
    );
    const sid = cookies['_s'] || cookies['scanner_sess'];
    if (sid) delete sessions[sid];
    res.writeHead(302, { 'Set-Cookie': '_s=; Max-Age=0; Path=/', 'Location': '/' });
    return res.end();
  }

  // Dashboard
  if (urlPath === '/' || urlPath === '/index.php') {
    return renderIndex(sess || null, '', res);
  }

  // Token-routed API — match incoming path against session route tokens
  if (req.method === 'POST' && sess) {
    const token      = urlPath.slice(1); // strip leading /
    const handlerKey = Object.keys(sess.routes).find(k => sess.routes[k] === token);

    if (handlerKey) {
      const mockName = ROUTE_TO_MOCK[handlerKey];
      const mock     = MOCKS[mockName];
      if (mock) {
        const body = await parseBody(req);
        await new Promise(r => setTimeout(r, 400 + Math.random() * 400));
        res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
        return res.end(JSON.stringify(await mock(body)));
      }
    }

    // Unknown token — 404, no info leakage
    res.writeHead(404, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Not found' }));
  }

  // Unauthenticated POST to token path
  if (req.method === 'POST') {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Not authenticated' }));
  }

  res.writeHead(404);
  res.end('Not found');
});

// Bind ONLY to loopback — blocks all external network interfaces
server.listen(PORT, '127.0.0.1', () => {
  console.log('');
  console.log('  Security Scanner — Dev Server');
  console.log(`  http://localhost:${PORT}  (127.0.0.1 only — not reachable outside this machine)`);
  console.log('');
  console.log('  Password: scanner123');
  console.log('  All API endpoints perform real live lookups');
  console.log('  Ctrl+C to stop');
  console.log('');
});

// Refuse any connection not from 127.0.0.1 at the socket level
server.on('connection', socket => {
  if (socket.remoteAddress !== '127.0.0.1' && socket.remoteAddress !== '::1') {
    socket.destroy();
  }
});
