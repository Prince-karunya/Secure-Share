(function () {
  const form = document.getElementById('share-access-form');
  if (!form || form.dataset.clientEncrypted !== 'true') return;

  const status = document.getElementById('access-status');
  const result = document.getElementById('secure-preview-result');
  const csrf = form.querySelector('input[name="csrfmiddlewaretoken"]').value;
  let ocrWorkerPromise;

  function decodeBase64(value) {
    return Uint8Array.from(atob(value), character => character.charCodeAt(0));
  }

  async function deriveKey(password, salt, fragmentKey) {
    if (fragmentKey) {
      let encodedKey = fragmentKey.replace(/-/g, '+').replace(/_/g, '/');
      encodedKey += '='.repeat((4 - encodedKey.length % 4) % 4);
      const raw = decodeBase64(encodedKey);
      return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']);
    }
    const material = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' },
      material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
  }

  function maskText(text) {
    const patterns = [
      /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
      /\b\d{12}\b/g,
      /\b[A-Z]{5}\d{4}[A-Z]\b/gi,
      /\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z\d][Z\d][A-Z\d]\b/gi,
      /\b[A-Z]{2}\d{2}[A-Z0-9]{11,12}\b/gi,
      /\b(?:\+91[\s-]?)?[6-9]\d{9}\b/g,
      /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
      /(?<!\d)(?:\d[\s-]?){8,17}\d(?!\d)/g
    ];
    return patterns.reduce((value, pattern) =>
      value.replace(pattern, match => '•'.repeat(match.length)), text);
  }

  function hasSensitiveOcrText(text) {
    const normalized = text.normalize('NFKC').replace(/[\u200B-\u200D\uFEFF]/g, '');
    if (maskText(normalized) !== normalized) return true;

    const compact = normalized.replace(/\s+/g, '');
    if (/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(compact)) return true;
    if (/\b(?:gmail|outlook|hotmail|yahoo|icloud)\.(?:com|in|net|org)\b/i.test(compact)) return true;
    if (/\b(?:aadhaar|aadhar|pan|gstin|ifsc|account|phone|mobile|e-?mail|address)\b/i.test(normalized)) {
      return true;
    }

    const numberCandidates = normalized.match(/(?:[0-9OIl|][\s().:/+-]*){8,20}/g) || [];
    return numberCandidates.some(candidate => {
      const digits = candidate.replace(/[Oo]/g, '0').replace(/[Il|]/g, '1').replace(/\D/g, '');
      return digits.length >= 8 && digits.length <= 18;
    });
  }

  async function getOcrWorker() {
    if (!window.Tesseract) {
      await new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = 'https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/tesseract.min.js';
        script.onload = resolve;
        script.onerror = () => reject(new Error('The in-browser OCR library could not be loaded.'));
        document.head.appendChild(script);
      });
    }
    if (!ocrWorkerPromise) {
      ocrWorkerPromise = window.Tesseract.createWorker('eng', 1, {
        logger: message => {
          if (message.status === 'recognizing text' && message.progress) {
            status.textContent = `Scanning for sensitive text… ${Math.round(message.progress * 100)}%`;
          }
        }
      }).then(async worker => {
        await worker.setParameters({ tessedit_pageseg_mode: '11' });
        return worker;
      });
    }
    return ocrWorkerPromise;
  }

  async function redactCanvas(canvas) {
    status.textContent = 'Scanning this file in your browser for sensitive text…';
    const worker = await getOcrWorker();
    const { data } = await worker.recognize(canvas);
    const context = canvas.getContext('2d');
    let redactedLines = 0;
    let hasLineBoxes = false;
    const lines = data.lines && data.lines.length
      ? data.lines
      : (data.blocks || []).flatMap(block =>
        (block.paragraphs || []).flatMap(paragraph => paragraph.lines || []));
    for (const line of lines) {
      const text = line.text || (line.words || []).map(word => word.text).join(' ');
      if (!line.bbox || !hasSensitiveOcrText(text)) continue;
      hasLineBoxes = true;

      const padding = Math.max(3, Math.round((line.bbox.y1 - line.bbox.y0) * 0.15));
      const left = Math.max(0, line.bbox.x0 - padding);
      const top = Math.max(0, line.bbox.y0 - padding);
      const right = Math.min(canvas.width, line.bbox.x1 + padding);
      const bottom = Math.min(canvas.height, line.bbox.y1 + padding);
      context.fillStyle = '#111827';
      context.fillRect(left, top, right - left, bottom - top);
      redactedLines += 1;
    }
    if (!lines.length && data.words && data.words.length) {
      const wordRows = new Map();
      for (const word of data.words) {
        if (!word.bbox) continue;
        const row = Math.round((word.bbox.y0 + word.bbox.y1) / 2 / 10);
        const words = wordRows.get(row) || [];
        words.push(word);
        wordRows.set(row, words);
      }
      for (const words of wordRows.values()) {
        const text = words.map(word => word.text).join(' ');
        if (!hasSensitiveOcrText(text)) continue;
        const left = Math.max(0, Math.min(...words.map(word => word.bbox.x0)) - 3);
        const top = Math.max(0, Math.min(...words.map(word => word.bbox.y0)) - 3);
        const right = Math.min(canvas.width, Math.max(...words.map(word => word.bbox.x1)) + 3);
        const bottom = Math.min(canvas.height, Math.max(...words.map(word => word.bbox.y1)) + 3);
        context.fillStyle = '#111827';
        context.fillRect(left, top, right - left, bottom - top);
        redactedLines += 1;
      }
    }
    if (!hasLineBoxes && hasSensitiveOcrText(data.text || '')) {
      context.fillStyle = '#111827';
      context.fillRect(0, 0, canvas.width, canvas.height);
      redactedLines += 1;
    }
    return redactedLines;
  }

  async function loadPdfJs() {
    if (!window.pdfjsLib) {
      await new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js';
        script.onload = resolve;
        script.onerror = () => reject(new Error('PDF preview library could not be loaded.'));
        document.head.appendChild(script);
      });
    }
    return window.pdfjsLib;
  }

  async function showPdf(buffer, maskSensitive) {
    const pdfjs = await loadPdfJs();
    pdfjs.GlobalWorkerOptions.workerSrc =
      'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
    const pdf = await pdfjs.getDocument({ data: buffer }).promise;
    let redactedLines = 0;
    for (let pageNumber = 1; pageNumber <= Math.min(pdf.numPages, 50); pageNumber++) {
      const page = await pdf.getPage(pageNumber);
      const baseViewport = page.getViewport({ scale: 1 });
      const scale = Math.min(3, 1800 / baseViewport.width, 2400 / baseViewport.height);
      const viewport = page.getViewport({ scale });
      const canvas = document.createElement('canvas');
      canvas.className = 'img-fluid d-block mb-3 mx-auto';
      canvas.setAttribute('role', 'img');
      canvas.setAttribute('aria-label', `PDF page ${pageNumber} preview`);
      canvas.width = viewport.width;
      canvas.height = viewport.height;
      await page.render({ canvasContext: canvas.getContext('2d'), viewport }).promise;
      if (maskSensitive) redactedLines += await redactCanvas(canvas);
      const displayScale = Math.min(1, 1200 / Math.max(canvas.width, canvas.height));
      if (displayScale < 1) {
        const preview = await createImageBitmap(canvas);
        canvas.width = Math.max(1, Math.round(preview.width * displayScale));
        canvas.height = Math.max(1, Math.round(preview.height * displayScale));
        canvas.getContext('2d').drawImage(preview, 0, 0, canvas.width, canvas.height);
        preview.close();
      }
      result.appendChild(canvas);
    }
    return redactedLines;
  }

  async function loadJsPdf() {
    if (!window.jspdf) {
      await new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = 'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.2/jspdf.umd.min.js';
        script.onload = resolve;
        script.onerror = () => reject(new Error('The PDF download library could not be loaded.'));
        document.head.appendChild(script);
      });
    }
    return window.jspdf.jsPDF;
  }

  async function createMaskedPdf(buffer) {
    const pdfjs = await loadPdfJs();
    pdfjs.GlobalWorkerOptions.workerSrc =
      'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
    const JsPdf = await loadJsPdf();
    const sourcePdf = await pdfjs.getDocument({ data: buffer }).promise;
    let outputPdf;
    let redactedLines = 0;

    for (let pageNumber = 1; pageNumber <= sourcePdf.numPages; pageNumber++) {
      const page = await sourcePdf.getPage(pageNumber);
      const baseViewport = page.getViewport({ scale: 1 });
      const scale = Math.min(3, 1800 / baseViewport.width, 2400 / baseViewport.height);
      const viewport = page.getViewport({ scale });
      const canvas = document.createElement('canvas');
      canvas.width = viewport.width;
      canvas.height = viewport.height;
      await page.render({ canvasContext: canvas.getContext('2d'), viewport }).promise;
      redactedLines += await redactCanvas(canvas);

      const orientation = baseViewport.width > baseViewport.height ? 'landscape' : 'portrait';
      if (!outputPdf) {
        outputPdf = new JsPdf({
          orientation,
          unit: 'pt',
          format: [baseViewport.width, baseViewport.height],
          compress: true
        });
      } else {
        outputPdf.addPage([baseViewport.width, baseViewport.height], orientation);
      }
      outputPdf.addImage(
        canvas,
        'PNG',
        0,
        0,
        baseViewport.width,
        baseViewport.height
      );
      page.cleanup();
    }

    if (!redactedLines) {
      throw new Error('No sensitive text was detected, so the download was blocked.');
    }
    return new Blob([outputPdf.output('arraybuffer')], { type: 'application/pdf' });
  }

  async function createMaskedDownload(info, plaintext, originalBlob) {
    if (info.content_type.startsWith('text/')) {
      const text = maskText(new TextDecoder().decode(plaintext));
      return {
        blob: new Blob([text], { type: info.content_type }),
        fileName: info.file_name
      };
    }

    if (info.content_type === 'application/pdf') {
      return {
        blob: await createMaskedPdf(plaintext),
        fileName: info.file_name
      };
    }

    if (info.content_type.startsWith('image/')) {
      const bitmap = await createImageBitmap(originalBlob);
      const scale = Math.min(2.5, 3000 / Math.max(bitmap.width, bitmap.height));
      const canvas = document.createElement('canvas');
      canvas.width = Math.max(1, Math.round(bitmap.width * scale));
      canvas.height = Math.max(1, Math.round(bitmap.height * scale));
      canvas.getContext('2d').drawImage(bitmap, 0, 0, canvas.width, canvas.height);
      bitmap.close();
      const redactedLines = await redactCanvas(canvas);
      if (!redactedLines) {
        throw new Error('No sensitive text was detected, so the download was blocked.');
      }
      const maskedBlob = await new Promise(resolve => canvas.toBlob(resolve, 'image/png'));
      if (!maskedBlob) throw new Error('The masked image could not be created.');
      return {
        blob: maskedBlob,
        fileName: `${info.file_name.replace(/\.[^.]+$/, '')}.png`
      };
    }

    throw new Error('This file type cannot be safely masked for download.');
  }

  async function present(info, plaintext) {
    const blob = new Blob([plaintext], { type: info.content_type });
    if (info.action === 'download') {
      const download = info.mask_sensitive
        ? await createMaskedDownload(info, plaintext, blob)
        : { blob, fileName: info.file_name };
      const url = URL.createObjectURL(download.blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = download.fileName;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 60000);
      status.textContent = info.mask_sensitive
        ? 'Your masked download is ready. Automated masking can miss sensitive text; review the file carefully.'
        : 'Your decrypted download is ready.';
      return;
    }

    result.replaceChildren();
    result.className = 'mt-3 p-3 border rounded bg-white';
    let redactedLines = 0;
    if (info.content_type.startsWith('text/')) {
      const pre = document.createElement('pre');
      pre.className = 'secure-preview text-break';
      let text = new TextDecoder().decode(plaintext);
      if (info.mask_sensitive) {
        const maskedText = maskText(text);
        redactedLines = (maskedText.match(/•+/g) || []).length;
        text = maskedText;
      }
      pre.textContent = text;
      result.appendChild(pre);
    } else if (info.content_type === 'application/pdf') {
      redactedLines = await showPdf(plaintext, info.mask_sensitive);
      if (info.mask_sensitive && !redactedLines) {
        throw new Error('No sensitive text was detected, so the preview is hidden to avoid showing unmasked content.');
      }
    } else {
      if (info.mask_sensitive) {
        const bitmap = await createImageBitmap(blob);
        const scale = Math.min(2.5, 3000 / Math.max(bitmap.width, bitmap.height));
        const canvas = document.createElement('canvas');
        canvas.className = 'img-fluid';
        canvas.setAttribute('role', 'img');
        canvas.setAttribute('aria-label', `Masked preview of ${info.file_name}`);
        canvas.width = Math.max(1, Math.round(bitmap.width * scale));
        canvas.height = Math.max(1, Math.round(bitmap.height * scale));
        canvas.getContext('2d').drawImage(bitmap, 0, 0, canvas.width, canvas.height);
        bitmap.close();
        redactedLines = await redactCanvas(canvas);
        if (!redactedLines) {
          throw new Error('No sensitive text was detected, so the preview is hidden to avoid showing unmasked content.');
        }
        result.appendChild(canvas);
      } else {
        const image = document.createElement('img');
        image.className = 'img-fluid';
        image.alt = info.file_name;
        image.src = URL.createObjectURL(blob);
        result.appendChild(image);
      }
    }
    status.textContent = info.mask_sensitive
      ? `Preview ready. Masked ${redactedLines} detected region(s). Automated masking can miss sensitive text; review carefully.`
      : 'Protected preview is ready.';
  }

  form.addEventListener('submit', async event => {
    event.preventDefault();
    const action = event.submitter ? event.submitter.value : '';
    const passwordInput = form.querySelector('input[name="password"]');
    const password = passwordInput ? passwordInput.value : '';
    const data = new FormData();
    data.set('action', action);
    data.set('password', password);
    status.textContent = 'Checking access…';
    result.replaceChildren();
    try {
      const response = await fetch(form.dataset.accessUrl, {
        method: 'POST',
        body: data,
        headers: { 'X-CSRFToken': csrf },
        credentials: 'same-origin'
      });
      const info = await response.json();
      if (!response.ok) throw new Error(info.error || 'This link is not available.');
      status.textContent = 'Retrieving encrypted file…';
      const fileResponse = await fetch(info.download_url);
      if (!fileResponse.ok) throw new Error('Private storage could not return this file.');
      const ciphertext = await fileResponse.arrayBuffer();
      if (ciphertext.byteLength !== info.file_size + 16) {
        throw new Error('The encrypted file did not pass its size check.');
      }
      status.textContent = 'Decrypting in this browser…';
      const fragmentKey = new URLSearchParams(location.hash.slice(1)).get('key');
      const key = await deriveKey(password, decodeBase64(info.salt), fragmentKey);
      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: decodeBase64(info.nonce) }, key, ciphertext
      );
      await present(info, plaintext);
      if (action === 'view') {
        document.addEventListener('contextmenu', event => event.preventDefault());
        document.addEventListener('visibilitychange', () => {
          result.style.visibility = document.hidden ? 'hidden' : 'visible';
        });
      }
    } catch (error) {
      result.replaceChildren();
      status.textContent = error.message || 'The file could not be decrypted.';
    }
  });
})();
