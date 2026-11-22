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
    for (const line of data.lines || []) {
      const hasPatternMatch = maskText(line.text) !== line.text;
      const hasLabeledValue = /\b(?:aadhaar|aadhar|pan|gstin|ifsc|account|phone|mobile|email|address)\b/i.test(line.text)
        && /[:#-]\s*\S/.test(line.text);
      if (!hasPatternMatch && !hasLabeledValue) continue;

      const padding = Math.max(3, Math.round((line.bbox.y1 - line.bbox.y0) * 0.15));
      const left = Math.max(0, line.bbox.x0 - padding);
      const top = Math.max(0, line.bbox.y0 - padding);
      const right = Math.min(canvas.width, line.bbox.x1 + padding);
      const bottom = Math.min(canvas.height, line.bbox.y1 + padding);
      context.fillStyle = '#111827';
      context.fillRect(left, top, right - left, bottom - top);
      redactedLines += 1;
    }
    return redactedLines;
  }

  async function showPdf(buffer, maskSensitive) {
    if (!window.pdfjsLib) {
      await new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js';
        script.onload = resolve;
        script.onerror = () => reject(new Error('PDF preview library could not be loaded.'));
        document.head.appendChild(script);
      });
    }
    const pdfjs = window.pdfjsLib;
    pdfjs.GlobalWorkerOptions.workerSrc =
      'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
    const pdf = await pdfjs.getDocument({ data: buffer }).promise;
    let redactedLines = 0;
    for (let pageNumber = 1; pageNumber <= Math.min(pdf.numPages, 50); pageNumber++) {
      const page = await pdf.getPage(pageNumber);
      const initialViewport = page.getViewport({ scale: 1.3 });
      const scale = Math.min(1, 2400 / Math.max(initialViewport.width, initialViewport.height));
      const viewport = page.getViewport({ scale: 1.3 * scale });
      const canvas = document.createElement('canvas');
      canvas.className = 'img-fluid d-block mb-3 mx-auto';
      canvas.setAttribute('role', 'img');
      canvas.setAttribute('aria-label', `PDF page ${pageNumber} preview`);
      canvas.width = viewport.width;
      canvas.height = viewport.height;
      await page.render({ canvasContext: canvas.getContext('2d'), viewport }).promise;
      if (maskSensitive) redactedLines += await redactCanvas(canvas);
      result.appendChild(canvas);
    }
    return redactedLines;
  }

  async function present(info, plaintext) {
    const blob = new Blob([plaintext], { type: info.content_type });
    if (info.action === 'download') {
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = info.file_name;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 60000);
      status.textContent = 'Your decrypted download is ready.';
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
    } else {
      if (info.mask_sensitive) {
        const bitmap = await createImageBitmap(blob);
        const scale = Math.min(1, 2400 / Math.max(bitmap.width, bitmap.height));
        const canvas = document.createElement('canvas');
        canvas.className = 'img-fluid';
        canvas.setAttribute('role', 'img');
        canvas.setAttribute('aria-label', `Masked preview of ${info.file_name}`);
        canvas.width = Math.max(1, Math.round(bitmap.width * scale));
        canvas.height = Math.max(1, Math.round(bitmap.height * scale));
        canvas.getContext('2d').drawImage(bitmap, 0, 0, canvas.width, canvas.height);
        bitmap.close();
        redactedLines = await redactCanvas(canvas);
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
      status.textContent = error.message || 'The file could not be decrypted.';
    }
  });
})();
