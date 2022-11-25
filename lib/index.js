// Module dependencies.
var Strategy = require('./strategy');


/**
 * Creates a new `{@link Strategy}` object.
 *
 * The `{@link Strategy}` constructor is a top-level function exported by the
 * `passport-local` module.
 *
 * @example
 * var Strategy = require('passport-http-dpop');
 * var strategy = new Strategy(function(username, password, cb) {
 *   // ...
 * });
 */
exports = module.exports = Strategy;

/**
 * Creates a new `{@link Strategy}` object.
 *
 * @example
 * var dpop = require('passport-http-dpop');
 * var strategy = new dpop.Strategy(function(username, password, cb) {
 *   // ...
 * });
 */
exports.Strategy = Strategy;
