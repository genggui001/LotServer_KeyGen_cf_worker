// Constants
const TEMPLATE_OLD_BASE64 = "sia8J04iD1PiLYY6HskT3qaWG9BG0DToiBjmjSYNeBPgtCJdOxHgC1BhBFZnwSr0mCmSq4buek+Ewe+DAgoa3NJQHw5qP2DaxBmrkKZFICnIHLO0BOq2n1mZP79ivTc6WEcEXc6j8yY2x0Pjo2ZEURPs90IF5ArzLLMMU0LMXr2WI34CqTJvOCPoME5NIPlC8gvfvq7v+EM=";
const TEMPLATE_NEW_BASE64 = "51/zXff+SqvCOqEJuijIKMnIACnLbWCpMsOLw3sZPKpbzl4Hlt8+E+ZAQ2lNAm5d5SsACWsae1jv22rc8eWEuMg4t7o2jSqSC6fnHLbuGjp+C87ugvWEjtuOxE09TPyHlZMA42M39AmZ/jftPGV8Pk9RdIFUNX90gOiLx8K06oRY2GiIAQvYwCTzCA9xEwJSYx/hEBEP2lRGGx21nsCofQ==";
const KEY = "apx-section1";

// Utility functions
function __ROL4__(decimal, bits) {
  decimal = decimal >>> 0; // Ensure unsigned 32-bit
  const binary = decimal.toString(2).padStart(32, '0');
  return parseInt(binary.substring(bits) + binary.substring(0, bits), 2) >>> 0;
}

function _INT32(val) {
  return val >>> 0; // Force unsigned 32-bit integer
}

function base64ToUint8Array(base64) {
  const binary = atob(base64);
  const array = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    array[i] = binary.charCodeAt(i);
  }
  return array;
}

function hexDump(data, len = null) {
  if (len === null) {
    len = data.length;
  }
  let output = '';
  for (let i = 0; i < len; i++) {
    let hex = data[i].toString(16).padStart(2, '0');
    output += hex + ' ';
    if ((i + 1) % 16 === 0) output += '\n';
  }
  output += '\n';
  return output;
}

// Core encryption/decryption functions
function APX_ProtInitContext(Id, IdLen, Key, KeyLen, ProtContext) {
  let result = KeyLen;
  let v6 = 0;
  let v7 = 0;

  ProtContext[0] = 0;
  ProtContext[1] = 0;
  
  if (IdLen) {
    while (true) {
      v7 = 0;
      let v8 = 0;
      
      if (IdLen) {
        do {
          const v9 = Id[v8];
          const v10 = 8 * v8++;
          v7 = _INT32(v7 | (v9 << v10));
        } while (v8 < IdLen && v8 <= 3);
      }
      
      if (IdLen <= 3)
        break;
        
      const v11 = Id.subarray(4);
      const v12 = IdLen - 4;
      
      let v13 = 0;
      if (v12) {
        let v14 = 0;
        do {
          const v15 = v11[v14];
          const v16 = 8 * v14++;
          v13 = _INT32(v13 | (v15 << v16));
        } while (v12 > v14 && v14 <= 3);
      }
      
      if (v12 <= 3) {
        ProtContext[1] = _INT32(ProtContext[1] + v13);
        ProtContext[0] = _INT32(v6 + v7);
        break;
      }
      
      v6 = _INT32(v6 + v7);
      ProtContext[1] = _INT32(ProtContext[1] + v13);
      IdLen = v12 - 4;
      ProtContext[0] = v6;
      
      if (!IdLen)
        break;
        
      Id = v11.subarray(4);
    }
  }
  
  let v17 = result;
  let v18 = 0;
  
  do {
    let v23;
    if (v18 < v17 && result) {
      let v19 = 0;
      let v20 = 0;
      do {
        const v21 = Key[v18 + v20];
        const v22 = 8 * v20++;
        v19 = _INT32(v19 | (v21 << v22));
      } while (v20 < result && v20 <= 3);
      v23 = _INT32(v19 - 1515870811);
    } else {
      v23 = 2779096485; // -1515870811 unsigned
    }
    
    ProtContext[v18 / 4 + 2] = v23;
    v18 += 4;
    result = result - 4;
  } while (v18 != 32);
  
  return result;
}

function APX_ProtUpdateContext(ProtContext) {
  const edx = _INT32(ProtContext[1] + 0x74656E78);
  const _tmp = _INT32(ProtContext[0] + 0x45505041);

  const v2 = _INT32(ProtContext[2] + __ROL4__(_tmp ^ edx, edx & 0x1F));
  const v3 = _INT32(ProtContext[3] + __ROL4__(edx ^ v2, v2 & 0x1F));
  const v4 = _INT32(ProtContext[4] + __ROL4__(v3 ^ v2, v3 & 0x1F));
  const v5 = _INT32(ProtContext[5] + __ROL4__(v4 ^ v3, v4 & 0x1F));
  const v6 = _INT32(ProtContext[6] + __ROL4__(v5 ^ v4, v5 & 0x1F));
  const v7 = _INT32(ProtContext[7] + __ROL4__(v6 ^ v5, v6 & 0x1F));
  
  const result = _INT32(ProtContext[8] + __ROL4__(v7 ^ v6, v7 & 0x1F));
  ProtContext[0] = _INT32(result);
  ProtContext[1] = _INT32(ProtContext[9] + __ROL4__(result ^ v7, result & 0x1F));

  return result;
}

function APX_ProtUninitContext(ProtContext) {
  return 0;
}

// Version >= 3.11.20.10
function APX_ProtDecrypt_New(Id, IdLen, Key, KeyLen, CipherText, CipherTextLen, OutPlainText) {
  let v8 = CipherTextLen;
  let v7 = 0;
  let v9 = 0;
  
  const ProtContext = new Uint32Array(12);
  APX_ProtInitContext(Id, IdLen, Key, KeyLen, ProtContext);
  
  if (v8) {
    let i = 0;
    while (true) {
      let v11 = 0;
      let v12 = 0;
      
      do {
        const v13 = v12;
        const v14 = 8 * v12++;
        v11 = _INT32(v11 | (CipherText[v7 + v13] << v14));
      } while (v12 < v8 && v12 <= 3);
      
      APX_ProtUpdateContext(ProtContext);
      
      let v15 = 0;
      let v16 = _INT32(v11 - i - ProtContext[0]);
      
      do {
        const v17 = v15++;
        OutPlainText[v9 + v17] = v16 & 0xFF;
        v16 >>= 8;
      } while (v15 < v8 && v15 <= 3);
      
      if (v8 <= 4)
        break;
        
      v7 += 4;
      v9 += 4;
      v8 -= 4;
      i = v11;
    }
  }
  
  APX_ProtUninitContext(ProtContext);
}

// Version >= 3.11.20.10
function APX_ProtEncrypt_New(Id, IdLen, Key, KeyLen, PlainText, PlainTextLen, OutCipherText) {
  let v8 = PlainTextLen;
  let v7 = 0;
  let v9 = 0;
  
  const ProtContext = new Uint32Array(12);
  APX_ProtInitContext(Id, IdLen, Key, KeyLen, ProtContext);
  
  if (v8) {
    let v10 = 0;
    
    while (true) {
      let v11 = 0;
      let v12 = 0;
      
      do {
        const v13 = v12;
        const v14 = 8 * v12++;
        v11 = _INT32(v11 | (PlainText[v7 + v13] << v14));
      } while (v12 < v8 && v12 <= 3);
      
      APX_ProtUpdateContext(ProtContext);
      
      let v15 = 0;
      v10 = _INT32(v11 + ProtContext[0] + v10);
      let v16 = v10;
      
      do {
        const v17 = v15++;
        OutCipherText[v9 + v17] = v16 & 0xFF;
        v16 >>= 8;
      } while (v15 < v8 && v15 <= 3);
      
      if (v8 <= 4)
        break;
        
      v7 += 4;
      v9 += 4;
      v8 -= 4;
    }
  }
  
  APX_ProtUninitContext(ProtContext);
}

// LotServer < 3.11.20.10
function APX_ProtDecrypt(Id, IdLen, Key, KeyLen, CipherText, CipherTextLen, OutPlainText) {
  let v7 = CipherTextLen;
  
  const ProtContext = new Uint32Array(12);
  APX_ProtInitContext(Id, IdLen, Key, KeyLen, ProtContext);

  for (let i = 0; v7; v7 -= 4) {
    let v10 = 0;
    let v11 = 0;
    
    if (v7) {
      do {
        const v13 = CipherText[i + v11];
        const v14 = _INT32(8 * v11++);
        v10 = _INT32(v10 | (v13 << v14));
      } while (v11 < v7 && v11 <= 3);
      
      const v15 = i;
      APX_ProtUpdateContext(ProtContext);
      
      let v16 = _INT32(v10 - ProtContext[0]);
      let v17 = 0;
      
      do {
        const v18 = v17++;
        OutPlainText[i + v18] = v16 & 0xFF;
        v16 >>= 8;
      } while (v17 < v7 && v17 <= 3);
      
    } else {
      APX_ProtUpdateContext(ProtContext);
    }
    
    if (v7 <= 4)
      break;
      
    i += 4;
  }
  
  APX_ProtUninitContext(ProtContext);
}

// LotServer < 3.11.20.10
function APX_ProtEncrypt(Id, IdLen, Key, KeyLen, PlainText, PlainTextLen, OutCipherText) {
  let v7 = PlainTextLen;
  
  const ProtContext = new Uint32Array(12);
  APX_ProtInitContext(Id, IdLen, Key, KeyLen, ProtContext);
  
  for (let i = 0; v7; v7 -= 4) {
    let v10 = 0;
    let v11 = 0;
    
    if (v7) {
      do {
        const v13 = PlainText[i + v11];
        const v14 = _INT32(8 * v11++);
        v10 = _INT32(v10 | (v13 << v14));
      } while (v11 < v7 && v11 <= 3);
      
      const v15 = i;
      APX_ProtUpdateContext(ProtContext);
      
      let v16 = _INT32(ProtContext[0] + v10);
      let v17 = 0;
      
      do {
        const v18 = v17++;
        OutCipherText[i + v18] = v16 & 0xFF;
        v16 >>= 8;
      } while (v17 < v7 && v17 <= 3);
      
    } else {
      APX_ProtUpdateContext(ProtContext);
    }
    
    if (v7 <= 4)
      break;
      
    i += 4;
  }
  
  APX_ProtUninitContext(ProtContext);
}

// License manipulation functions
function decode_lic(buffer, lic_len, output = true) {
  const key = new Uint8Array(KEY.length);
  for (let i = 0; i < KEY.length; i++) {
    key[i] = KEY.charCodeAt(i);
  }
  
  const lic_info = new Uint8Array(lic_len);
  
  if (lic_len === 0x98) {
    // Old version
    APX_ProtDecrypt(key, key.length, key, key.length, buffer, lic_len, lic_info);
  } else {
    // New version
    APX_ProtDecrypt_New(key, key.length, key, key.length, buffer, lic_len, lic_info);
  }
  
  if (output) {
    // Extract license as a string
    let license = '';
    for (let i = 0; i < 0x10; i++) {
      license += String.fromCharCode(lic_info[0x40 + i]);
    }
    
    // Read values with little-endian byte order
    const maxSession = lic_info[0x70] | (lic_info[0x71] << 8) | (lic_info[0x72] << 16) | (lic_info[0x73] << 24);
    const maxTcpAccSession = lic_info[0x74] | (lic_info[0x75] << 8) | (lic_info[0x76] << 16) | (lic_info[0x77] << 24);
    const maxCompSession = lic_info[0x78] | (lic_info[0x79] << 8) | (lic_info[0x7A] << 16) | (lic_info[0x7B] << 24);
    const maxByteCacheSession = lic_info[0x7C] | (lic_info[0x7D] << 8) | (lic_info[0x7E] << 16) | (lic_info[0x7F] << 24);
    const maxBandwidth = lic_info[0x68] | (lic_info[0x69] << 8) | (lic_info[0x6A] << 16) | (lic_info[0x6B] << 24);
    
    const year = lic_info[0x60] | (lic_info[0x61] << 8);
    const month = lic_info[0x62];
    const day = lic_info[0x63];
    
    console.log(`License: ${license}`);
    console.log(`MaxSession: ${maxSession}`);
    console.log(`MaxTcpAccSession: ${maxTcpAccSession}`);
    console.log(`MaxCompSession: ${maxCompSession}`);
    console.log(`MaxByteCacheSession: ${maxByteCacheSession}`);
    console.log(`MaxBandwidth: ${maxBandwidth}`);
    console.log(`ExpireDate: ${year}-${month}-${day}`);
  }
  
  return lic_info;
}

function modify_expire(lic_info, year, month = 12, day = 31) {
  lic_info[0x60] = year & 0xFF;
  lic_info[0x61] = (year >> 8) & 0xFF;
  lic_info[0x62] = month;
  lic_info[0x63] = day;
}

function modify_mac(lic_info, mac, output = true) {
  // Parse MAC address
  const mac_arr = mac.split(':');
  
  // Create mac_bin (original MAC bytes)
  const mac_bin = new Uint8Array(6);
  for (let i = 0; i < 6; i++) {
    mac_bin[i] = parseInt(mac_arr[i], 16);
  }
  
  // Create mac_hash - this is critical, must match PHP behavior exactly
  const mac_hash = new Uint8Array(16);
  
  // First initialize the first 6 values
  for (let i = 0; i < 6; i++) {
    mac_hash[i] = mac_bin[i] + i;
  }
  
  // Then calculate remaining values, using the updated mac_hash values
  for (let i = 6; i < 16; i++) {
    mac_hash[i] = mac_hash[i % 6] + i;
  }
  
  // Generate license string
  let license = '';
  for (let i = 0; i < 8; i++) {
    const calc = (mac_hash[i] + mac_hash[i + 8]) & 0xFF;
    license += calc.toString(16).padStart(2, '0').toUpperCase();
  }
  
  if (output) {
    console.log(`(license ${license})`);
  }
  
  // Store license in lic_info
  for (let i = 0; i < license.length; i++) {
    lic_info[0x40 + i] = license.charCodeAt(i);
  }
  
  // Fill the rest with zeros
  for (let i = license.length; i < 0x10; i++) {
    lic_info[0x40 + i] = 0;
  }
}

function modify_hash(lic_info, version) {
  const key = new Uint8Array(KEY.length);
  for (let i = 0; i < KEY.length; i++) {
    key[i] = KEY.charCodeAt(i);
  }
  
  if (version === 1) {
    // Version 1 hash calculation
    const tmp = new Uint8Array(lic_info.length);
    for (let i = 0; i < lic_info.length; i++) {
      tmp[i] = lic_info[i];
    }
    
    // Clear first 0x20 bytes
    for (let i = 0; i < 0x20; i++) {
      tmp[i] = 0;
    }
    
    // Generate random number between 0 and 0x7FFFFFFF
    const hash = Math.floor(Math.random() * 0x7FFFFFFF);
    const hashStr = hash.toString();
    for (let i = 0; i < hashStr.length; i++) {
      tmp[i] = hashStr.charCodeAt(i);
    }
    
    // Calculate hash_ret
    const hash_ret = new Uint8Array(0x20);
    APX_ProtEncrypt_New(key, key.length, key, key.length, tmp, 0x20, hash_ret);
    
    // Store hash in lic_info
    lic_info[0x98] = hash & 0xFF;
    lic_info[0x99] = (hash >> 8) & 0xFF;
    lic_info[0x9A] = (hash >> 16) & 0xFF;
    lic_info[0x9B] = (hash >> 24) & 0xFF;
    
    // Update first 0x20 bytes with hash_ret
    for (let i = 0; i < 0x20; i++) {
      lic_info[i] = hash_ret[i];
    }
  }
}

// Main handler function for Cloudflare Worker
async function handleRequest(request) {
  const url = new URL(request.url);
  const macAddress = url.searchParams.get('mac') || "00:00:00:00:00:00";
  const version = parseInt(url.searchParams.get('ver') || '1');
  const verbose = url.searchParams.get('v') === 'true';
  
  if (macAddress.length !== 17) { // 00:00:00:00:00:00
    return new Response("Invalid mac address\n", {
      status: 400,
      headers: { 'Content-Type': 'text/plain' }
    });
  }
  
  // Determine which template to use based on version
  let lic_len, templateBuffer;
  
  if (version === 0) {
    lic_len = 0x98;
    templateBuffer = base64ToUint8Array(TEMPLATE_OLD_BASE64);
  } else if (version === 1) {
    lic_len = 0xA0;
    templateBuffer = base64ToUint8Array(TEMPLATE_NEW_BASE64);
  } else {
    return new Response("undefined version\n", {
      status: 400,
      headers: { 'Content-Type': 'text/plain' }
    });
  }
  
  if (templateBuffer.length !== lic_len) {
    return new Response("template lic error!\n", {
      status: 500,
      headers: { 'Content-Type': 'text/plain' }
    });
  }
  
  try {
    // Decode license
    const lic_info = decode_lic(templateBuffer, lic_len, verbose);
    
    // Zero out fields
    for (let i = 0x68; i < 0x80; i++) {
      lic_info[i] = 0;
    }
    
    // Modify license
    modify_mac(lic_info, macAddress, verbose);
    modify_expire(lic_info, 2099, 12, 31);
    modify_hash(lic_info, version);
    
    if (verbose) {
      console.log(hexDump(lic_info));
    }
    
    // Encrypt the modified license
    const key = new Uint8Array(KEY.length);
    for (let i = 0; i < KEY.length; i++) {
      key[i] = KEY.charCodeAt(i);
    }
    
    const modified_lic = new Uint8Array(lic_len);
    
    if (version === 0) {
      APX_ProtEncrypt(key, key.length, key, key.length, lic_info, lic_len, modified_lic);
    } else {
      APX_ProtEncrypt_New(key, key.length, key, key.length, lic_info, lic_len, modified_lic);
    }
    
    if (verbose) {
      console.log("\nHexView:");
      console.log(hexDump(modified_lic));
      console.log("\n----> Output: out.lic");
    }
    
    // Return the modified license file
    return new Response(modified_lic, {
      status: 200,
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': 'attachment; filename=out.lic',
        'Accept-Ranges': 'bytes',
        'Content-Length': String(lic_len)
      }
    });
  } catch (error) {
    console.error('Error generating license:', error);
    return new Response("Error generating license: " + error.message, {
      status: 500,
      headers: { 'Content-Type': 'text/plain' }
    });
  }
}

// Entry point for Cloudflare Worker
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});