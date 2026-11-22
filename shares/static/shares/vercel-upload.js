(function () {
  const form = document.getElementById('share-upload-form');
  if (!form || form.dataset.clientEncrypted !== 'true') return;

  const status = document.getElementById('upload-status');
  const progress = form.querySelector('.progress');
  const progressBar = form.querySelector('.progress-bar');
  const fileInput = form.querySelector('input[type="file"]');
  const submitButton = form.querySelector('button[type="submit"]');
  const maxFileSize = 50_000_000 - 16;

  function csrfToken() {
    return form.querySelector('input[name="csrfmiddlewaretoken"]').value;
  }

  function decodeBase64(value) {
    return Uint8Array.from(atob(value), character => character.charCodeAt(0));
  }

  function encodeBase64Url(value) {
    return btoa(String.fromCharCode(...value))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  async function encryptionKey(password, salt) {
    if (!password) {
      const rawKey = crypto.getRandomValues(new Uint8Array(32));
      return crypto.subtle.importKey(
        'raw', rawKey, { name: 'AES-GCM' }, true, ['encrypt']
      );
    }
    const material = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' },
      material, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
    );
  }

  async function postForm(url, data) {
    data.append('csrfmiddlewaretoken', csrfToken());
    const response = await fetch(url, {
      method: 'POST',
      body: data,
      headers: { 'X-CSRFToken': csrfToken() },
      credentials: 'same-origin'
    });
    const result = await response.json();
    if (!response.ok) {
      if (result.errors) {
        const messages = Object.values(result.errors).flat().map(error => error.message);
        throw new Error(messages.join(' '));
      }
      throw new Error(result.error || 'The secure upload could not be completed.');
    }
    return result;
  }

  function putObject(url, ciphertext) {
    return new Promise((resolve, reject) => {
      const request = new XMLHttpRequest();
      request.open('PUT', url);
      request.setRequestHeader('Content-Type', 'application/octet-stream');
      request.upload.onprogress = event => {
        if (event.lengthComputable) {
          const percent = Math.round(event.loaded / event.total * 100);
          progressBar.style.width = percent + '%';
          progressBar.textContent = percent + '%';
        }
      };
      request.onload = () => request.status >= 200 && request.status < 300
        ? resolve()
        : reject(new Error('Private storage rejected the encrypted upload.'));
      request.onerror = () => reject(new Error('Network error while uploading to private storage.'));
      request.onabort = () => reject(new Error('Upload was cancelled.'));
      request.send(ciphertext);
    });
  }

  form.addEventListener('submit', async event => {
    event.preventDefault();
    const file = fileInput.files[0];
    if (!file) {
      status.textContent = 'Choose a file first.';
      return;
    }
    if (file.size < 1 || file.size > maxFileSize) {
      status.textContent = 'Choose a file no larger than 50 MB on the free deployment.';
      return;
    }

    submitButton.disabled = true;
    progress.hidden = false;
    status.textContent = 'Preparing encrypted upload…';
    try {
      const metadata = new FormData(form);
      metadata.delete('file');
      metadata.set('file_name', file.name);
      metadata.set('file_size', String(file.size));
      const init = await postForm(form.dataset.initUrl, metadata);
      const salt = decodeBase64(init.salt);
      const nonce = decodeBase64(init.nonce);
      const password = form.querySelector('input[name="password_enabled"]').checked
        ? form.querySelector('input[name="password"]').value : '';
      const key = await encryptionKey(password, salt);
      status.textContent = 'Encrypting in this browser…';
      const plaintext = await file.arrayBuffer();
      const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, plaintext);
      status.textContent = 'Uploading encrypted bytes…';
      await putObject(init.upload_url, ciphertext);
      const finalizeData = new FormData();
      finalizeData.set('token', init.token);
      const finalized = await postForm(init.finalize_url, finalizeData);
      let destination = finalized.created_url;
      if (!finalized.password_protected) {
        destination += '#key=' + encodeBase64Url(new Uint8Array(await crypto.subtle.exportKey('raw', key)));
      }
      window.location.assign(destination);
    } catch (error) {
      status.textContent = error.message || 'The secure upload failed. Please try again.';
      submitButton.disabled = false;
    }
  });
})();
