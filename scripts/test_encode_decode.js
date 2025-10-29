#!/usr/bin/env node
// Encapsula/scripts/test_encode_decode.js
//
// End-to-end test script to verify encode/decode works correctly.
// This script creates a test image, encodes a message, then decodes it.
//
// Usage:
//   node Encapsula/scripts/test_encode_decode.js
//
// Requirements:
//   npm install pngjs jpeg-js

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

// ============================================================================
// ENCRYPTION / KEY DERIVATION (from encode.ts)
// ============================================================================

function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha512');
}

function encryptMessage(message, password) {
  const salt = crypto.randomBytes(32);
  const key = deriveKey(password, salt);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = Buffer.concat([
    cipher.update(message, 'utf8'),
    cipher.final(),
  ]);
  return { salt, iv, encrypted };
}

function decryptPayload(payload, password) {
  if (payload.length < 48) throw new Error('Payload too short');
  const salt = payload.slice(0, 32);
  const iv = payload.slice(32, 48);
  const encrypted = payload.slice(48);
  const key = deriveKey(password, salt);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  const out = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return out.toString('utf8');
}

// ============================================================================
// PAYLOAD WRAPPING (from encode.ts)
// ============================================================================

function makePayload(messageBuffer) {
  const version = Buffer.alloc(4);
  version.writeUInt32BE(1, 0);
  const len = Buffer.alloc(4);
  len.writeUInt32BE(messageBuffer.length, 0);
  return Buffer.concat([version, len, messageBuffer]);
}

// ============================================================================
// GENERIC APPEND METHOD (from encode.ts)
// ============================================================================

function embedGeneric(fileBuffer, data) {
  const marker = Buffer.from('<<ENCAPSULA_HIDDEN>>', 'utf8');
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(data.length, 0);
  return Buffer.concat([fileBuffer, marker, lenBuf, data, marker]);
}

function extractGeneric(fileBuffer) {
  try {
    const marker = Buffer.from('<<ENCAPSULA_HIDDEN>>', 'utf8');
    const startIndex = fileBuffer.lastIndexOf(marker);
    if (startIndex === -1) return null;

    const lengthStart = startIndex + marker.length;
    if (lengthStart + 4 > fileBuffer.length) return null;
    const dataLength = fileBuffer.readUInt32BE(lengthStart);
    if (dataLength <= 0 || dataLength > 10 * 1024 * 1024) return null;

    const dataStart = lengthStart + 4;
    const dataEnd = dataStart + dataLength;
    if (dataEnd > fileBuffer.length) return null;

    return fileBuffer.slice(dataStart, dataEnd);
  } catch {
    return null;
  }
}

// ============================================================================
// LSB EMBEDDING (PNG) (from encode.ts)
// ============================================================================

function embedLSBPNG(fileBuffer, payload) {
  const PNG = require('pngjs').PNG;
  const payloadWithHeader = makePayload(payload);

  // Convert to bits
  const bits = [];
  for (let i = 0; i < payloadWithHeader.length; i++) {
    const byte = payloadWithHeader[i];
    for (let b = 7; b >= 0; b--) bits.push((byte >> b) & 1);
  }

  const png = PNG.sync.read(fileBuffer);
  const { width, height, data } = png;
  const capacity = width * height * 3;

  if (bits.length + 32 > capacity) {
    throw new Error('Not enough capacity in PNG image for payload');
  }

  // Encode length
  const lenBits = [];
  const payloadLen = payloadWithHeader.length;
  for (let i = 31; i >= 0; i--) lenBits.push((payloadLen >> i) & 1);
  const allBits = lenBits.concat(bits);

  // Embed bits into LSBs
  let bitIdx = 0;
  for (let i = 0; i < data.length && bitIdx < allBits.length; i += 4) {
    if (bitIdx < allBits.length) {
      data[i] = (data[i] & 0xfe) | allBits[bitIdx++];
    }
    if (bitIdx < allBits.length) {
      data[i + 1] = (data[i + 1] & 0xfe) | allBits[bitIdx++];
    }
    if (bitIdx < allBits.length) {
      data[i + 2] = (data[i + 2] & 0xfe) | allBits[bitIdx++];
    }
  }

  const out = PNG.sync.write({ width, height, data });
  return out;
}

// ============================================================================
// LSB EXTRACTION (PNG) (from decode.ts)
// ============================================================================

function extractLSBPNG(fileBuffer) {
  const PNG = require('pngjs').PNG;
  const png = PNG.sync.read(fileBuffer);
  const { width, height, data } = png;
  const totalPixels = width * height;
  const capacityBits = totalPixels * 3;

  const readBits = (neededBits) => {
    const bits = [];
    let bitIdx = 0;
    for (let i = 0; i < data.length && bitIdx < neededBits; i += 4) {
      if (bitIdx < neededBits) (bits.push(data[i] & 1), bitIdx++);
      if (bitIdx < neededBits) (bits.push(data[i + 1] & 1), bitIdx++);
      if (bitIdx < neededBits) (bits.push(data[i + 2] & 1), bitIdx++);
    }
    return bits;
  };

  // Read length (first 32 bits)
  const lenBits = readBits(32);
  if (lenBits.length < 32) return null;
  let payloadLen = 0;
  for (let i = 0; i < 32; i++) payloadLen = (payloadLen << 1) | (lenBits[i] & 1);
  if (payloadLen <= 0 || payloadLen > Math.floor((capacityBits - 32) / 8)) return null;

  // Read payload
  const needBits = 32 + payloadLen * 8;
  const collected = [];
  let bIdx = 0;
  for (let i = 0; i < data.length && bIdx < needBits; i += 4) {
    if (bIdx < needBits) (collected.push(data[i] & 1), bIdx++);
    if (bIdx < needBits) (collected.push(data[i + 1] & 1), bIdx++);
    if (bIdx < needBits) (collected.push(data[i + 2] & 1), bIdx++);
  }
  if (collected.length < needBits) return null;

  const payloadBits = collected.slice(32);
  const bytes = Buffer.alloc(payloadLen);
  for (let i = 0; i < payloadLen; i++) {
    let val = 0;
    for (let b = 0; b < 8; b++) val = (val << 1) | (payloadBits[i * 8 + b] & 1);
    bytes[i] = val;
  }
  return bytes;
}

// ============================================================================
// PAYLOAD UNWRAPPING (from decode.ts)
// ============================================================================

function unwrapPayload(extracted) {
  if (extracted.length < 8) return extracted;

  try {
    const version = extracted.readUInt32BE(0);
    const maybeLen = extracted.readUInt32BE(4);

    if (
      version === 1 &&
      Number.isFinite(maybeLen) &&
      maybeLen > 0 &&
      maybeLen <= 10 * 1024 * 1024 &&
      extracted.length >= 8 + maybeLen
    ) {
      return extracted.slice(8, 8 + maybeLen);
    } else {
      return extracted;
    }
  } catch {
    return extracted;
  }
}

// ============================================================================
// TEST HELPER: CREATE SIMPLE PNG
// ============================================================================

function createTestPNG(width, height) {
  const PNG = require('pngjs').PNG;
  const png = new PNG({ width, height });

  // Fill with random-ish pattern
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const idx = (width * y + x) << 2;
      png.data[idx] = (x * 7 + y * 13) % 256; // R
      png.data[idx + 1] = (x * 11 + y * 17) % 256; // G
      png.data[idx + 2] = (x * 13 + y * 19) % 256; // B
      png.data[idx + 3] = 255; // A
    }
  }

  return PNG.sync.write(png);
}

// ============================================================================
// MAIN TEST
// ============================================================================

function runTest() {
  console.log('='.repeat(70));
  console.log('Encapsula End-to-End Encode/Decode Test');
  console.log('='.repeat(70));

  const testMessage = 'Hello, World! This is a secret message.\nLine 2: Testing multiline.\nLine 3: 🎉';
  const testPassword = 'test_password_123';

  console.log('\n[1] Creating test PNG image (100x100)...');
  let testPNG;
  try {
    testPNG = createTestPNG(100, 100);
    console.log('✓ PNG created (' + testPNG.length + ' bytes)');
  } catch (e) {
    console.error('✗ Failed to create PNG:', e.message);
    console.error('  Make sure pngjs is installed: npm install pngjs');
    process.exit(1);
  }

  console.log('\n[2] Encrypting message...');
  const { salt, iv, encrypted } = encryptMessage(testMessage, testPassword);
  const payload = Buffer.concat([salt, iv, encrypted]);
  console.log('✓ Encrypted payload size:', payload.length, 'bytes');

  // ========================================================================
  // TEST 1: Generic Append Method
  // ========================================================================
  console.log('\n' + '='.repeat(70));
  console.log('TEST 1: Generic Append Method');
  console.log('='.repeat(70));

  console.log('\n[3] Encoding with generic append method...');
  const encodedAppend = embedGeneric(testPNG, payload);
  console.log('✓ Encoded file size:', encodedAppend.length, 'bytes');

  console.log('\n[4] Extracting with generic append method...');
  const extractedAppend = extractGeneric(encodedAppend);
  if (!extractedAppend) {
    console.error('✗ Failed to extract payload');
    process.exit(1);
  }
  console.log('✓ Extracted payload size:', extractedAppend.length, 'bytes');

  console.log('\n[5] Unwrapping payload...');
  const unwrappedAppend = unwrapPayload(extractedAppend);
  console.log('✓ Unwrapped payload size:', unwrappedAppend.length, 'bytes');

  console.log('\n[6] Decrypting...');
  let decryptedAppend;
  try {
    decryptedAppend = decryptPayload(unwrappedAppend, testPassword);
    console.log('✓ Decrypted message:', JSON.stringify(decryptedAppend));
  } catch (e) {
    console.error('✗ Decryption failed:', e.message);
    process.exit(1);
  }

  if (decryptedAppend === testMessage) {
    console.log('\n✓✓✓ TEST 1 PASSED: Message matches! ✓✓✓');
  } else {
    console.error('\n✗✗✗ TEST 1 FAILED: Message mismatch! ✗✗✗');
    console.error('Expected:', JSON.stringify(testMessage));
    console.error('Got:', JSON.stringify(decryptedAppend));
    process.exit(1);
  }

  // ========================================================================
  // TEST 2: LSB PNG Method
  // ========================================================================
  console.log('\n' + '='.repeat(70));
  console.log('TEST 2: LSB PNG Method');
  console.log('='.repeat(70));

  console.log('\n[7] Encoding with LSB PNG method...');
  let encodedLSB;
  try {
    encodedLSB = embedLSBPNG(testPNG, payload);
    console.log('✓ Encoded file size:', encodedLSB.length, 'bytes');
  } catch (e) {
    console.error('✗ Failed to encode with LSB:', e.message);
    process.exit(1);
  }

  console.log('\n[8] Extracting with LSB PNG method...');
  let extractedLSB;
  try {
    extractedLSB = extractLSBPNG(encodedLSB);
    if (!extractedLSB) throw new Error('No payload extracted');
    console.log('✓ Extracted payload size:', extractedLSB.length, 'bytes');
  } catch (e) {
    console.error('✗ Failed to extract with LSB:', e.message);
    process.exit(1);
  }

  console.log('\n[9] Unwrapping payload...');
  const unwrappedLSB = unwrapPayload(extractedLSB);
  console.log('✓ Unwrapped payload size:', unwrappedLSB.length, 'bytes');
  console.log('  First 16 bytes (hex):', unwrappedLSB.slice(0, 16).toString('hex'));
  console.log('  Expected salt (hex):', salt.slice(0, 16).toString('hex'));

  console.log('\n[10] Decrypting...');
  let decryptedLSB;
  try {
    decryptedLSB = decryptPayload(unwrappedLSB, testPassword);
    console.log('✓ Decrypted message:', JSON.stringify(decryptedLSB));
  } catch (e) {
    console.error('✗ Decryption failed:', e.message);
    console.error('  Unwrapped payload length:', unwrappedLSB.length);
    console.error('  First 64 bytes (hex):', unwrappedLSB.slice(0, 64).toString('hex'));
    process.exit(1);
  }

  if (decryptedLSB === testMessage) {
    console.log('\n✓✓✓ TEST 2 PASSED: Message matches! ✓✓✓');
  } else {
    console.error('\n✗✗✗ TEST 2 FAILED: Message mismatch! ✗✗✗');
    console.error('Expected:', JSON.stringify(testMessage));
    console.error('Got:', JSON.stringify(decryptedLSB));
    process.exit(1);
  }

  // ========================================================================
  // SUMMARY
  // ========================================================================
  console.log('\n' + '='.repeat(70));
  console.log('ALL TESTS PASSED! ✓✓✓');
  console.log('='.repeat(70));
  console.log('\nThe encode/decode logic is working correctly.');
  console.log('If the UI still fails, the issue is likely with:');
  console.log('  - File upload/reading');
  console.log('  - Password input handling');
  console.log('  - State management in the UI');
  console.log('  - Missing dependencies (pngjs/jpeg-js)');
  console.log('\nRun this to install dependencies:');
  console.log('  npm install pngjs jpeg-js');
  console.log('='.repeat(70));
}

// Run the test
try {
  runTest();
} catch (e) {
  console.error('\n✗✗✗ TEST FAILED WITH ERROR ✗✗✗');
  console.error(e);
  process.exit(1);
}
