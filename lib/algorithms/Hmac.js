/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const crypto = require('crypto');

module.exports = class Algorithms {
  constructor() {
  }

  sign({hashType, plaintext, sharedKey}, callback) {
    const signer = crypto.createHmac(hashType.toUpperCase(), sharedKey);
    signer.update(plaintext);
    const signature = signer.digest('base64');
    callback(null, signature);
  }

  verify({hashType, plaintext, sharedKey, signature}, callback) {
    const verifier = crypto.createHmac(hashType.toUpperCase(), sharedKey);
    verifier.update(plaintext);
    const verified = (signature === verifier.digest('base64'));
    callback(null, verified);
  }

};
