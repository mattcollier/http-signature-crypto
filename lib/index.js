/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const Algorithms = require('./Algorithms');
const algorithms = new Algorithms();
const {callbackify} = require('util');
const Ed25519 = require('./algorithms/Ed25519');
const Hmac = require('./algorithms/Hmac');
const Rsa = require('./algorithms/Rsa');

const api = {};
module.exports = api;

api.sign = (
  {algorithm, hashType, plaintext, privateKeyBase58, privateKeyPem, sharedKey},
  callback) => {
  const signer = api.use(algorithm);
  function fn() {
    return new Promise((resolve, reject) => {
      if(signer === undefined) {
        return reject(new Error(`Unknown algorithm '${algorithm}'.`));
      }
      signer.sign(
        {hashType, plaintext, privateKeyBase58, privateKeyPem, sharedKey},
        (err, result) => {
          if(err) {
            return reject(err);
          }
          resolve(result);
        });
    });
  }

  if(callback && typeof callback === 'function') {
    const cbFn = callbackify(fn);
    return cbFn(callback);
  }
  return fn();
};

api.verify = ({
  algorithm, hashType, plaintext, publicKeyBase58, publicKeyPem,
  sharedKey, signature
}, callback) => {
  const verifier = api.use(algorithm);
  function fn() {
    return new Promise((resolve, reject) => {
      if(verifier === undefined) {
        return reject(new Error(`Unknown algorithm '${algorithm}'.`));
      }
      verifier.verify({
        hashType, plaintext, publicKeyBase58, publicKeyPem, sharedKey,
        signature
      }, (err, result) => {
        if(err) {
          return reject(err);
        }
        resolve(result);
      });
    });
  }

  if(callback && typeof callback === 'function') {
    const cbFn = callbackify(fn);
    return cbFn(callback);
  }
  return fn();
};

api.use = (name, algorithm) => algorithms.use(name, algorithm);

api.use('ed25519', new Ed25519());
api.use('hmac', new Hmac());
api.use('rsa', new Rsa());
