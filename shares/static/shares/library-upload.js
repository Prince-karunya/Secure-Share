(function () {
  const form = document.getElementById('library-upload-form');
  if (!form) return;

  const input = document.getElementById('library-file');
  const status = document.getElementById('library-upload-status');
  const button = form.querySelector('button[type="submit"]');

  function decodeBase64(value) {
    return Uint8Array.from(atob(value), character => character.charCodeAt(0));
  }

  async function postForm(url, data) {
    const csrf = form.querySelector('input[name="csrfmiddlewaretoken"]').value;
    const response = await fetch(url, {
      method: 'POST',
      body: data,
      headers: { 'X-CSRFToken': csrf },
      credentials: 'same-origin'
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'The encrypted upload could not be completed.');
    return result;
  }

  form.addEventListener('submit', async event => {
    event.preventDefault();
    const file = input.files[0];
    if (!file) {
      status.textContent = 'Choose a document first.';
      return;
    }

    button.disabled = true;
    status.textContent = 'Preparing private encrypted storage…';
    try {
      const metadata = new FormData();
      metadata.set('file_name', file.name);
      metadata.set('file_size', String(file.size));
      const init = await postForm(form.dataset.initUrl, metadata);
      const key = await crypto.subtle.importKey(
        'raw',
        decodeBase64(init.library_key),
        { name: 'AES-GCM' },
        false,
        ['encrypt']
      );
      status.textContent = 'Encrypting this document in your browser…';
      const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: decodeBase64(init.nonce) },
        key,
        await file.arrayBuffer()
      );

      if (init.upload_url.startsWith('http')) {
        status.textContent = 'Uploading encrypted bytes to private storage…';
        const response = await fetch(init.upload_url, {
          method: 'PUT',
          body: ciphertext,
          headers: { 'Content-Type': 'application/octet-stream' }
        });
        if (!response.ok) throw new Error('Private storage rejected the encrypted upload.');
        const finalized = new FormData();
        finalized.set('token', init.token);
        status.textContent = 'Verifying the stored document…';
        await postForm(form.dataset.finalizeUrl, finalized);
      } else {
        status.textContent = 'Saving the encrypted document…';
        const csrf = form.querySelector('input[name="csrfmiddlewaretoken"]').value;
        const upload = new FormData();
        upload.set('csrfmiddlewaretoken', csrf);
        upload.set('encrypted_file', new Blob([ciphertext], {
          type: 'application/octet-stream'
        }), file.name + '.enc');
        const response = await fetch(init.upload_url, {
          method: 'POST',
          body: upload,
          headers: { 'X-CSRFToken': csrf },
          credentials: 'same-origin'
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || 'The encrypted document could not be saved.');
      }

      status.textContent = 'Document safely stored. Opening your library…';
      window.location.assign(form.dataset.libraryUrl);
    } catch (error) {
      status.textContent = error.message || 'The encrypted upload failed. Please try again.';
      button.disabled = false;
    }
  });
})();
