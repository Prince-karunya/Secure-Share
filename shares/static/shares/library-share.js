(function () {
  const form = document.getElementById('library-share-form');
  if (!form) return;

  const status = document.getElementById('library-share-status');
  const button = form.querySelector('button[type="submit"]');

  function decodeBase64(value) {
    return Uint8Array.from(atob(value), character => character.charCodeAt(0));
  }

  function encodeBase64Url(value) {
    return btoa(String.fromCharCode(...value))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  async function postForm(url, data) {
    const csrf = form.querySelector('input[name="csrfmiddlewaretoken"]').value;
    data.set('csrfmiddlewaretoken', csrf);
    const response = await fetch(url, {
      method: 'POST',
      body: data,
      headers: { 'X-CSRFToken': csrf },
      credentials: 'same-origin'
    });
    const result = await response.json();
    if (!response.ok) {
      if (result.errors) {
        const errors = Object.values(result.errors).flat().map(error => error.message);
        throw new Error(errors.join(' '));
      }
      throw new Error(result.error || 'The secure share could not be created.');
    }
    return result;
  }

  async function shareKey(password, salt) {
    if (!password) {
      const rawKey = crypto.getRandomValues(new Uint8Array(32));
      return {
        key: await crypto.subtle.importKey(
          'raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt']
        ),
        rawKey
      };
    }
    const material = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return {
      key: await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' },
        material,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
      ),
      rawKey: null
    };
  }

  async function uploadCiphertext(url, ciphertext, csrf) {
    if (url.startsWith('http')) {
      const response = await fetch(url, {
        method: 'PUT',
        body: ciphertext,
        headers: { 'Content-Type': 'application/octet-stream' }
      });
      if (!response.ok) throw new Error('Private storage rejected the encrypted share.');
      return;
    }
    const upload = new FormData();
    upload.set('csrfmiddlewaretoken', csrf);
    upload.set('encrypted_file', new Blob([ciphertext], {
      type: 'application/octet-stream'
    }), 'encrypted-share.enc');
    const response = await fetch(url, {
      method: 'POST',
      body: upload,
      headers: { 'X-CSRFToken': csrf },
      credentials: 'same-origin'
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'The encrypted share could not be saved.');
    return result;
  }

  form.addEventListener('submit', async event => {
    event.preventDefault();
    button.disabled = true;
    const csrf = form.querySelector('input[name="csrfmiddlewaretoken"]').value;
    try {
      status.textContent = 'Preparing the new share…';
      const options = new FormData(form);
      const init = await postForm(form.dataset.initUrl, options);

      status.textContent = 'Retrieving your encrypted library document…';
      const sourceResponse = await fetch(init.source_url, { credentials: 'same-origin' });
      if (!sourceResponse.ok) throw new Error('The library document could not be retrieved.');
      const encryptedLibraryFile = await sourceResponse.arrayBuffer();
      if (encryptedLibraryFile.byteLength !== init.file_size + 16) {
        throw new Error('The library document did not pass its encrypted size check.');
      }

      const libraryKey = await crypto.subtle.importKey(
        'raw', decodeBase64(init.library_key), { name: 'AES-GCM' }, false, ['decrypt']
      );
      status.textContent = 'Preparing the share encryption in your browser…';
      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: decodeBase64(init.library_nonce) },
        libraryKey,
        encryptedLibraryFile
      );
      const passwordInput = form.querySelector('input[name="password"]');
      const password = form.querySelector('input[name="password_enabled"]').checked
        ? passwordInput.value : '';
      const salt = decodeBase64(init.salt);
      const encryptedShareKey = await shareKey(password, salt);
      const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: decodeBase64(init.nonce) },
        encryptedShareKey.key,
        plaintext
      );

      status.textContent = 'Uploading the separately encrypted share…';
      const localResult = await uploadCiphertext(init.upload_url, ciphertext, csrf);
      let finalized = localResult;
      if (!finalized) {
        const finalizeData = new FormData();
        finalizeData.set('token', init.token);
        finalized = await postForm(init.finalize_url, finalizeData);
      }

      let destination = finalized.created_url;
      if (!finalized.password_protected) {
        const fragmentKey = encodeBase64Url(encryptedShareKey.rawKey);
        localStorage.setItem('secureshare-key-' + init.token, fragmentKey);
        destination += '#key=' + encodeURIComponent(fragmentKey);
      }
      status.textContent = 'Share created. Opening your private link…';
      window.location.assign(destination);
    } catch (error) {
      status.textContent = error.message || 'The secure share could not be created.';
      button.disabled = false;
    }
  });
})();
