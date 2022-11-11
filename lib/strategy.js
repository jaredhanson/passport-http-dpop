// Module dependencies.
var passport = require('passport-strategy')
  , jws = require('jws')
  , jwk2pem = require('jwk-to-pem')
  , crypto = require('crypto')
  , base64url = require('base64url')
  , util = require('util')
  , utils = require('./utils');

function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) { throw new TypeError('HTTPDPoPStrategy requires a verify function'); }
  
  passport.Strategy.call(this);
  this.name = 'dpop';
  this._realm = options.realm;
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
}

// Inherit from `passport.Strategy`.
util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req, options) {
  var authorization = req.headers['authorization'];
  if (!authorization) { return this.fail(this._challenge()); }
  
  var parts = authorization.split(' ')
  if (parts.length < 2) { return this.fail(400); }
  
  var scheme = parts[0]
    , token = parts[1];
  
  if (!/DPoP/i.test(scheme)) { return this.fail(this._challenge()); }
  
  var proof = req.headers['dpop'];
  console.log(proof);
  
  var jwt = jws.decode(proof, { json: true });
  console.log(jwt)
  
  if (!jwt.header.typ) {
    return this.fail(this._challenge('invalid_dpop_proof', 'Missing type header'));
  }
  if (jwt.header.typ != 'dpop+jwt') {
    return this.fail(this._challenge('invalid_dpop_proof', 'Incorrect type'));
  }
  // TODO: Check `alg` header
  if (!jwt.header.jwk) {
    return this.fail(this._challenge('invalid_dpop_proof', 'Missing JSON Web Key header'));
  }
  if (!jwt.payload.jti) {
    return this.fail(this._challenge('invalid_dpop_proof', 'Missing JWT ID claim'));
  }
  if (!jwt.payload.htm) {
    return this.fail(this._challenge('invalid_dpop_proof', 'Missing HTTP method claim'));
  }
  if (!jwt.payload.htu) {
    return this.fail(this._challenge('invalid_dpop_proof', 'Missing HTTP target URI claim'));
  }
  // TODO: Check iat
  if (!jwt.payload.ath) {
    return this.fail(this._challenge('invalid_dpop_proof', 'Missing access token hash claim'));
  }
  
  if (req.method !== jwt.payload.htm) {
    return this.fail(this._challenge('invalid_dpop_proof', 'HTTP method claim does not match'));
  }
  
  var url = utils.originalURL(req);
  
  // TODO: compare without query
  if (url !== jwt.payload.htu) {
    return this.fail(this._challenge('invalid_dpop_proof', 'HTTP target URI claim does not match'));
  }
  
  // TODO: implement nonce support
  
  var hash = crypto.createHash('sha256').update(token).digest();
  if (base64url.encode(hash) !== jwt.payload.ath) {
    return this.fail(this._challenge('invalid_dpop_proof', 'Access token hash does not match'));
  }
  
  var pem = jwk2pem(jwt.header.jwk);
  console.log(pem);
  
  var ok = jws.verify(proof, 'ES256', pem);
  if (!ok) { return this.fail(this._challenge('invalid_dpop_proof')); } // TODO: add error message
  
  
  var self = this;
  
  function verified(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) {
      if (typeof info == 'string') {
        info = { message: info }
      }
      info = info || {};
      return self.fail(self._challenge('invalid_token', info.message));
    }
    self.success(user, info);
  }
  
  if (self._passReqToCallback) {
    this._verify(req, token, verified);
  } else {
    this._verify(token, verified);
  }
};

Strategy.prototype._challenge = function(code, desc, uri) {
  var challenge = "DPoP";
  if (this._realm) {
    challenge += ' realm="' + this._realm + '"';
  }
  if (code) {
    challenge += ', error="' + code + '"';
  }
  if (desc && desc.length) {
    challenge += ', error_description="' + desc + '"';
  }
  
  return challenge;
};

// Export `Strategy`.
module.exports = Strategy;
