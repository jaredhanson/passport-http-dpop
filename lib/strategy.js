// Module dependencies.
var passport = require('passport-strategy')
  , util = require('util');

function Strategy(options, verify) {
  
}

// Inherit from `passport.Strategy`.
util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req, options) {
  
};

// Export `Strategy`.
module.exports = Strategy;
