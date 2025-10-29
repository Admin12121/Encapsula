#!/usr/bin/env node
// Encapsula/scripts/decrypt_payload.js
//
// Helper to extract an appended Encapsula payload and decrypt it with a password.
// This script only supports the "append" embedding method (marker + length + payload).
//
// Usage:
//   node Encapsula/scripts/decrypt_payload.js <encoded-file> <password>
//
// If <password> is omitted, the script will prompt for it (visible input).
//
// Notes:
// - The appended payload format (as produced by the encoder's fallback) is:
//     [marker "<<ENCAPSULA_HIDDEN>>"][4-byte BE length][payload bytes][marker]
//   where payload bytes = [salt (32 bytes)] + [iv (16 bytes)] + [ciphertext].
// - Key derivation: PBKDF2(password, salt, 100000, 32, 'sha512')
// - Cipher: AES-256-CBC with IV (16 bytes)
//
// Security: This script prints the decrypted plaintext to stdout. Be careful
// when running in shared terminals or recording logs.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

function usageAndExit(msg) {
  if (msg) console.error(msg);
  console.error('\nUsage: node Encapsula/scripts/decrypt_payload.js <encoded-file> <password?>');
  console.error('If password is omitted, you will be prompted for it.');
  process.exit(msg ? 2 : 1);
}

function promptPassword(promptText) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    rl.question(promptText, (pw) => {
      rl.close();
      resolve(pw || '');
    });
  });
}

function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha512');
}

function decryptPayloadBuffer(payloadBuf, passwordBuf) {
  if (!Buffer.isBuffer(payloadBuf)) throw new Error('payload must be a Buffer');
  if (payloadBuf.length < 48) throw new Error('Payload too short to contain salt+iv+ciphertext');

  const salt = payloadBuf.slice(0, 32);
  const iv = payloadBuf.slice(32, 48);
  const encrypted = payloadBuf.slice(48);

  const key = deriveKey(passwordBuf.toString('utf8'), salt);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  const out = Buffer.concat([decipher.update(encrypted), (() => {
    try { return decipher.final(); } catch (e) { throw new Error('Decryption failed: ' + e.message); }
  })()]);
  return out.toString('utf8');
}

(async function main() {
  try {
    const argv = process.argv.slice(2);
    if (argv.length < 1) usageAndExit();

    const filePath = argv[0];
    if (!fs.existsSync(filePath)) usageAndExit('File not found: ' + filePath);

    let password = null;
    if (argv.length >= 2 && argv[1]) {
      password = argv[1];
    } else if (process.env.ENC_PASS) {
      password = process.env.ENC_PASS;
    } else {
      // Prompt (visible)
      password = await promptPassword('Password: ');
      if (!password) {
        usageAndExit('No password provided');
      }
    }

    const fileBuf = fs.readFileSync(filePath);
    const marker = Buffer.from('<<ENCAPSULA_HIDDEN>>', 'utf8');

    const markerIndex = fileBuf.lastIndexOf(marker);
    if (markerIndex === -1) {
      console.error('No appended Encapsula marker found in file.');
      console.error('This script only handles appended payloads. If the tool used LSB/DCT embedding, use the appropriate extractor.');
      process.exit(3);
    }

    const lenStart = markerIndex + marker.length;
    if (lenStart + 4 > fileBuf.length) {
      console.error('File contains marker but not enough bytes to read length header.');
      process.exit(4);
    }

    const declaredLen = fileBuf.readUInt32BE(lenStart);
    const dataStart = lenStart + 4;
    const dataEnd = dataStart + declaredLen;
    if (dataEnd > fileBuf.length) {
      console.error(`Declared payload length (${declaredLen}) extends past EOF (available bytes: ${Math.max(0, fileBuf.length - dataStart)}).`);
      process.exit(5);
    }

    const payload = fileBuf.slice(dataStart, dataEnd);

    // Optional: check for trailing marker after payload
    const trailingIdx = dataEnd;
    const hasTrailingMarker = (trailingIdx + marker.length <= fileBuf.length) &&
      fileBuf.slice(trailingIdx, trailingIdx + marker.length).equals(marker);

    if (!hasTrailingMarker) {
      console.warn('Warning: trailing marker not found after payload. File may be truncated or modified.');
    }

    // Decrypt
    let plaintext;
    try {
      plaintext = decryptPayloadBuffer(payload, Buffer.from(password, 'utf8'));
    } catch (e) {
      console.error('Failed to decrypt payload:', e.message);
      process.exit(6);
    }

    // Output plaintext. If binary content is expected, user should redirect or modify.
    console.log('\n----- Decrypted Message Start -----\n');
    console.log(plaintext);
    console.log('\n----- Decrypted Message End -----\n');
    process.exit(0);
  } catch (err) {
    console.error('Error:', err && err.message ? err.message : err);
    process.exit(10);
  }
})();
