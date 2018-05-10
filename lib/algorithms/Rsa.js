/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const crypto = require('crypto');

module.exports = class Algorithms {
  constructor() {
  }

  sign({hashType, plaintext, privateKeyPem}, callback) {
    const signer = crypto.createSign(hashType.toUpperCase());
    signer.update(plaintext);
    const signature = signer.sign(privateKeyPem, 'base64');
    callback(null, signature);
  }

  verify({hashType, plaintext, publicKeyPem, signature}, callback) {
    const verifier = crypto.createVerify(hashType.toUpperCase());
    verifier.update(plaintext);
    const verified = verifier.verify(publicKeyPem, signature, 'base64');
    callback(null, verified);
  }

};
