function strToArrayBuffer(str) {
  return new TextEncoder().encode(str);
}

function arrayBufferToStr(buffer) {
  return new TextDecoder().decode(buffer);
}

async function deriveKey(password, salt) {
  const pwdBuffer = strToArrayBuffer(password);
  const baseKey = await crypto.subtle.importKey(
    'raw',
    pwdBuffer,
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptMessage(plaintext, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(password, salt);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    strToArrayBuffer(plaintext)
  );
  const combined = new Uint8Array(salt.byteLength + iv.byteLength + encryptedBuffer.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.byteLength);
  combined.set(new Uint8Array(encryptedBuffer), salt.byteLength + iv.byteLength);
  return btoa(String.fromCharCode(...combined));
}

async function decryptMessage(base64Ciphertext, password) {
  try {
    const data = Uint8Array.from(atob(base64Ciphertext), c => c.charCodeAt(0));
    const salt = data.slice(0, 16);
    const iv = data.slice(16, 28);
    const ciphertext = data.slice(28);
    const key = await deriveKey(password, salt);
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      ciphertext
    );
    return arrayBufferToStr(decryptedBuffer);
  } catch {
    throw new Error('فشل فكّ التشفير: تأكد من كلمة المرور أو النص المشفر.');
  }
}

window.addEventListener('DOMContentLoaded', () => {
  const plaintextEl = document.getElementById('plaintext');
  const passwordEl = document.getElementById('password');
  const outputEl = document.getElementById('output');
  const encryptBtn = document.getElementById('encryptBtn');
  const decryptBtn = document.getElementById('decryptBtn');

  encryptBtn.addEventListener('click', async () => {
    const text = plaintextEl.value.trim();
    const pwd = passwordEl.value;
    if (!text) {
      alert('الرجاء إدخال نص للتشفير.');
      return;
    }
    if (!pwd) {
      alert('الرجاء إدخال كلمة المرور.');
      return;
    }
    try {
      outputEl.value = await encryptMessage(text, pwd);
    } catch {
      alert('حدث خطأ أثناء التشفير.');
    }
  });

  decryptBtn.addEventListener('click', async () => {
    const cipher = outputEl.value.trim();
    const pwd = passwordEl.value;
    if (!cipher) {
      alert('الرجاء إدخال النص المشفر.');
      return;
    }
    if (!pwd) {
      alert('الرجاء إدخال كلمة المرور.');
      return;
    }
    try {
      outputEl.value = await decryptMessage(cipher, pwd);
    } catch (err) {
      alert(err.message);
    }
  });
});
