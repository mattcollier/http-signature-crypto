/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const Algorithms = require('./Algorithms');
const algorithms = new Algorithms();
const {callbackify} = require('util');
const Ed25519 = require('./algorithms/Ed25519');

const api = {};
module.exports = api;

api.sign = (
  {algorithm, hashType, plaintext, privateKeyBase58, privateKeyPem},
  callback) => {
  const signer = api.use(algorithm);
  function fn() {
    return new Promise((resolve, reject) => {
      if(signer === undefined) {
        return reject(new Error(`Unknown algorithm '${algorithm}'.`));
      }
      signer.sign(
        {hashType, plaintext, privateKeyBase58, privateKeyPem},
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

api.verify = (
  {algorithm, hashType, plaintext, publicKeyBase58, publicKeyPem, signature},
  callback) => {
  const verifier = api.use(algorithm);
  function fn() {
    return new Promise((resolve, reject) => {
      if(verifier === undefined) {
        return reject(new Error(`Unknown algorithm '${algorithm}'.`));
      }
      verifier.verify(
        {hashType, plaintext, publicKeyBase58, publicKeyPem, signature},
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

api.use = (name, algorithm) => algorithms.use(name, algorithm);

api.use('ed25519', new Ed25519());
