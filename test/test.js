/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const chai = require('chai');
const mockData = require('./mock-data');
const should = chai.should();

// const {expect} = chai;
const hsc = require('..');

describe('http-signature-crypto', () => {

  describe('Promise API', () => {
    describe('sign API', () => {
      it('returns an error on an unknown algorithm', () => {
        return hsc.sign({algorithm: 'abc'})
          .catch(err => {
            should.exist(err);
            err.message.should.equal('Unknown algorithm \'abc\'.');
          });
      });
      describe('Ed25519', () => {
        it('creates a signature', () => {
          const plaintext = 'abc123';
          const {privateKeyBase58} = mockData.ed25519KeyPair;
          return hsc.sign({algorithm: 'ed25519', plaintext, privateKeyBase58})
            .then(signature => {
              should.exist(signature);
              signature.should.be.a('string');
              signature.should.equal(
                'q/tQqxBlhzSP+XTte7uYaaCyJXJvg8svdjV47E2rBrVI1fBIOAeKj5Jm7qB' +
                'kH0IL8CvKRboqHBCoITDrsT9DAQ==');
            });
        });
      });
    });
    describe('verify API', () => {
      it('returns an error on an unknown algorithm', () => {
        return hsc.verify({algorithm: 'abc'})
          .catch(err => {
            should.exist(err);
            err.message.should.equal('Unknown algorithm \'abc\'.');
          });
      });
      describe('Ed25519', () => {
        it('verifies a signature', () => {
          const plaintext = 'abc123';
          const {publicKeyBase58} = mockData.ed25519KeyPair;
          return hsc.verify({
            algorithm: 'ed25519', plaintext, publicKeyBase58,
            signature: 'q/tQqxBlhzSP+XTte7uYaaCyJXJvg8svdjV47E2rBrVI1fBIOAeK' +
              'j5Jm7qBkH0IL8CvKRboqHBCoITDrsT9DAQ=='
          }).then(verified => {
            should.exist(verified);
            verified.should.be.a('boolean');
            verified.should.be.true;
          });
        });
      });
    });
  });

  describe('Callback API', () => {
    describe('sign API', () => {
      it('returns an error on an unknown algorithm', done => {
        hsc.sign({algorithm: 'abc'}, (err, result) => {
          should.exist(err);
          should.not.exist(result);
          err.message.should.equal('Unknown algorithm \'abc\'.');
          done();
        });
      });
      describe('Ed25519', () => {
        it('creates a signature', done => {
          const plaintext = 'abc123';
          const {privateKeyBase58} = mockData.ed25519KeyPair;
          return hsc.sign(
            {algorithm: 'ed25519', plaintext, privateKeyBase58},
            (err, signature) => {
              should.not.exist(err);
              should.exist(signature);
              signature.should.be.a('string');
              signature.should.equal(
                'q/tQqxBlhzSP+XTte7uYaaCyJXJvg8svdjV47E2rBrVI1fBIOAeKj5Jm7qB' +
                'kH0IL8CvKRboqHBCoITDrsT9DAQ==');
              done();
            });
        });
      });
    });
    describe('verify API', () => {
      it('returns an error on an unknown algorithm', done => {
        hsc.verify({algorithm: 'abc'}, (err, result) => {
          should.exist(err);
          should.not.exist(result);
          err.message.should.equal('Unknown algorithm \'abc\'.');
          done();
        });
      });
    });
  });

});
