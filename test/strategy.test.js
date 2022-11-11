var chai = require('chai');
var Strategy = require('../lib/strategy');


describe('Strategy', function() {
  
  var strategy = new Strategy(function(token, cb) {
    throw new Error('verify function should not be called');
  });
  
  it('should be named dpop', function() {
    expect(strategy.name).to.equal('dpop');
  });
  
  it('should challenge request that lacks credentials', function(done) {
    var strategy = new Strategy(function(token, cb) {
      throw new Error('verify function should not be called');
    });
    
    chai.passport.use(strategy)
      .fail(function(challenge, status) {
        expect(challenge).to.equal('DPoP');
        expect(status).to.be.undefined;
        done();
      })
      .authenticate();
  });
  
});
