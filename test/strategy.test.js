var chai = require('chai');
var Strategy = require('../lib/strategy');


describe('Strategy', function() {
  
  var strategy = new Strategy(function(token, cb) {
    throw new Error('verify function should not be called');
  });
  
  it('should be named dpop', function() {
    expect(strategy.name).to.equal('dpop');
  });
  
  it('should authenticate request with valid credentials', function(done) {
    var strategy = new Strategy(function(token, cb) {
      expect(token).to.equal('Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU');
      return cb(null, { id: '248289761001' });
    });
    
    chai.passport.use(strategy)
      .request(function(req) {
        req.headers['authorization'] = 'DPoP Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU';
        req.headers['dpop'] = 'eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik' +
    'VDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCR' +
    'nMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JE' +
    'QSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIj' +
    'oiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0Z' +
    'WRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNF' +
    'c05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71E' +
    'OptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA';
      })
      .success(function(user, info) {
        expect(user).to.deep.equal({ id: '248289761001' });
        expect(info).to.be.undefined;
        done();
      })
      .authenticate();
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
