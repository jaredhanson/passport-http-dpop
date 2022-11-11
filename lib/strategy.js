// Module dependencies.
var passport = require('passport-strategy')
  , util = require('util');

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
  
};

Strategy.prototype._challenge = function(code, desc, uri) {
  var challenge = "DPoP";
  if (this._realm) {
    challenge += ' realm="' + this._realm + '"';
  }
  
  return challenge;
};

// Export `Strategy`.
module.exports = Strategy;
