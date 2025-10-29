#!/usr/bin/env node
/**
 * Encapsula File Diagnosis Script
 *
 * This script inspects an encoded file and shows exactly what's embedded in it.
 * Use this to debug why decoding might be failing.
 *
 * Usage:
 *   node scripts/diagnose_file.js <encoded-file> [password]
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Colors for terminal output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
};

function log(msg, color = '') {
  console.log(color + msg + colors.reset);
}

function header(msg) {
  console.log('');
  log('='.repeat(70), colors.bright);
  log(msg, colors.bright + colors.cyan);
  log('='.repeat(70), colors.bright);
  console.log('');
}

function success(msg) {
  log('✓ ' + msg, colors.green);
}

function error(msg) {
  log('✗ ' + msg, colors.red);
}

function warn(msg) {
  log('⚠ ' + msg, colors.yellow);
}

function info(msg) {
  log('  ' + msg, colors.blue);
}

// Check arguments
if (process.argv.length < 3) {
  console.error('Usage: node scripts/diagnose_file.js <encoded-file> [password]');
  process.exit(1);
}

const filePath = process.argv[2];
const password = process.argv.length >= 4 ? process.argv[3] : null;

if (!fs.existsSync(filePath)) {
  error('File not found: ' + filePath);
  process.exit(1);
}

// Read file
const fileBuffer = fs.readFileSync(filePath);
const fileStats = fs.statSync(filePath);

header('FILE INFORMATION');
info('Path: ' + filePath);
info('Size: ' + fileStats.size.toLocaleString() + ' bytes');
info('Type: ' + (path.extname(filePath) || 'unknown'));

// Check file signature
const signature = fileBuffer.slice(0, 4).toString('hex');
let fileType = 'Unknown';
if (signature.startsWith('ffd8')) fileType = 'JPEG';
else if (signature === '89504e47') fileType = 'PNG';
else if (signature.startsWith('424d')) fileType = 'BMP';
else if (signature === '25504446') fileType = 'PDF';

info('Detected format: ' + fileType);

// ============================================================================
// CHECK 1: Appended Marker
// ============================================================================

header('CHECK 1: Generic Append Method');

const marker = Buffer.from('<<ENCAPSULA_HIDDEN>>', 'utf8');
const markerIndex = fileBuffer.lastIndexOf(marker);

if (markerIndex === -1) {
  error('No appended marker found');
  info('This file does NOT use the generic append method');
} else {
  success('Appended marker found at offset ' + markerIndex);

  const lengthStart = markerIndex + marker.length;
  if (lengthStart + 4 <= fileBuffer.length) {
    const declaredLen = fileBuffer.readUInt32BE(lengthStart);
    info('Declared payload length: ' + declaredLen + ' bytes');

    const dataStart = lengthStart + 4;
    const dataEnd = dataStart + declaredLen;
    const available = Math.max(0, Math.min(declaredLen, fileBuffer.length - dataStart));

    if (available === declaredLen) {
      success('Payload fully available (' + available + ' bytes)');

      // Check for trailing marker
      if (dataEnd + marker.length <= fileBuffer.length) {
        const trailingMarker = fileBuffer.slice(dataEnd, dataEnd + marker.length);
        if (trailingMarker.equals(marker)) {
          success('Trailing marker found');
        } else {
          warn('Trailing marker missing or corrupted');
        }
      }

      // Show payload structure
      const payload = fileBuffer.slice(dataStart, dataEnd);
      info('First 32 bytes of payload (hex):');
      console.log('  ' + payload.slice(0, 32).toString('hex'));

      if (payload.length >= 48) {
        info('Payload structure appears valid (salt + iv + encrypted)');
        info('  Salt (first 16 bytes): ' + payload.slice(0, 16).toString('hex'));
        info('  IV (next 16 bytes):    ' + payload.slice(32, 48).toString('hex'));
        info('  Encrypted data:        ' + (payload.length - 48) + ' bytes');

        // Try to decrypt if password provided
        if (password) {
          console.log('');
          info('Attempting decryption with provided password...');
          try {
            const salt = payload.slice(0, 32);
            const iv = payload.slice(32, 48);
            const encrypted = payload.slice(48);
            const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha512');
            const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
            const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
            success('Decryption successful!');
            console.log('');
            log('Decrypted message:', colors.bright + colors.green);
            console.log(colors.cyan + '─'.repeat(70) + colors.reset);
            console.log(decrypted.toString('utf8'));
            console.log(colors.cyan + '─'.repeat(70) + colors.reset);
          } catch (e) {
            error('Decryption failed: ' + e.message);
            warn('The password might be incorrect');
          }
        } else {
          info('Provide a password as second argument to attempt decryption');
        }
      } else {
        warn('Payload too small (' + payload.length + ' bytes, expected at least 48)');
      }
    } else {
      error('Payload truncated (declared: ' + declaredLen + ', available: ' + available + ')');
    }
  } else {
    error('Not enough bytes after marker to read length header');
  }
}

// ============================================================================
// CHECK 2: LSB Embedding (PNG)
// ============================================================================

if (fileType === 'PNG') {
  header('CHECK 2: LSB Embedding (PNG)');

  try {
    const PNG = require('pngjs').PNG;
    const png = PNG.sync.read(fileBuffer);
    const { width, height, data } = png;

    success('PNG decoded: ' + width + 'x' + height + ' pixels');

    const capacityBits = width * height * 3;
    const capacityBytes = Math.floor((capacityBits - 32) / 8);
    info('LSB capacity: ' + capacityBytes + ' bytes');

    // Try to read length from LSBs
    const lenBits = [];
    let bitIdx = 0;
    for (let i = 0; i < data.length && bitIdx < 32; i += 4) {
      lenBits.push(data[i] & 1);
      bitIdx++;
      if (bitIdx < 32) { lenBits.push(data[i + 1] & 1); bitIdx++; }
      if (bitIdx < 32) { lenBits.push(data[i + 2] & 1); bitIdx++; }
    }

    let payloadLen = 0;
    for (let i = 0; i < 32; i++) {
      payloadLen = (payloadLen << 1) | (lenBits[i] & 1);
    }

    info('LSB length field: ' + payloadLen + ' bytes');

    if (payloadLen > 0 && payloadLen <= capacityBytes) {
      success('Length field appears valid');
      info('This file likely contains LSB-embedded data');

      // Extract first 64 bytes to show structure
      const needBits = 32 + Math.min(64, payloadLen) * 8;
      const collected = [];
      bitIdx = 0;
      for (let i = 0; i < data.length && bitIdx < needBits; i += 4) {
        if (bitIdx < needBits) { collected.push(data[i] & 1); bitIdx++; }
        if (bitIdx < needBits) { collected.push(data[i + 1] & 1); bitIdx++; }
        if (bitIdx < needBits) { collected.push(data[i + 2] & 1); bitIdx++; }
      }

      const sample = Buffer.alloc(Math.min(64, payloadLen));
      const payloadBits = collected.slice(32);
      for (let i = 0; i < sample.length; i++) {
        let val = 0;
        for (let b = 0; b < 8; b++) {
          val = (val << 1) | (payloadBits[i * 8 + b] & 1);
        }
        sample[i] = val;
      }

      info('First 32 bytes of LSB payload (hex):');
      console.log('  ' + sample.slice(0, 32).toString('hex'));

      // Check for version header
      if (sample.length >= 8) {
        const version = sample.readUInt32BE(0);
        const declaredLen = sample.readUInt32BE(4);
        if (version === 1) {
          success('Version header detected (version=' + version + ', len=' + declaredLen + ')');
          info('This is a wrapped LSB payload');
        } else {
          info('No version header detected (might be unwrapped)');
        }
      }
    } else {
      warn('Length field invalid (' + payloadLen + ')');
      info('This file likely does NOT contain LSB-embedded data');
    }
  } catch (e) {
    error('Failed to check LSB: ' + e.message);
    if (e.message.includes('Cannot find module')) {
      info('Install pngjs to check LSB: npm install pngjs');
    }
  }
}

// ============================================================================
// CHECK 3: DCT Embedding (JPEG)
// ============================================================================

if (fileType === 'JPEG') {
  header('CHECK 3: DCT Embedding (JPEG)');

  try {
    const jpeg = require('jpeg-js');
    const raw = jpeg.decode(fileBuffer, { useTArray: true });
    const { width, height } = raw;

    success('JPEG decoded: ' + width + 'x' + height + ' pixels');

    const blocksX = Math.floor(width / 8);
    const blocksY = Math.floor(height / 8);
    const capacityBits = blocksX * blocksY;
    const capacityBytes = Math.floor((capacityBits - 32) / 8);

    info('DCT capacity: ' + capacityBytes + ' bytes (' + blocksX + 'x' + blocksY + ' blocks)');
    info('Note: DCT extraction is complex and requires full decoder');
    warn('Use the main decode function to extract DCT-embedded data');
  } catch (e) {
    error('Failed to check DCT: ' + e.message);
    if (e.message.includes('Cannot find module')) {
      info('Install jpeg-js to check DCT: npm install jpeg-js');
    }
  }
}

// ============================================================================
// SUMMARY
// ============================================================================

header('SUMMARY');

console.log('This file contains:');
if (markerIndex >= 0) {
  success('Appended payload (generic method) - DETECTED');
} else {
  info('Appended payload (generic method) - NOT DETECTED');
}

if (fileType === 'PNG') {
  info('LSB embedding possibility - CHECK ABOVE');
} else if (fileType === 'JPEG') {
  info('DCT embedding possibility - CHECK ABOVE');
}

console.log('');
info('To decode in the app:');
info('  1. Make sure pngjs and jpeg-js are installed: npm install pngjs jpeg-js');
info('  2. Build the app: npm run build');
info('  3. Run the app: npm start');
info('  4. Go to Decode tab and upload this file');
info('  5. Enter the password used during encoding');
console.log('');
