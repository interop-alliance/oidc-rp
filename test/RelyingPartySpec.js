'use strict'

/**
 * Test dependencies
 */
const chai = require('chai')
const nock = require('nock')
const sinon = require('sinon')

/**
 * Assertions
 */
chai.use(require('sinon-chai'))
chai.use(require('chai-as-promised'))
chai.use(require('dirty-chai'))
chai.should()
const expect = chai.expect

/**
 * Code under test
 */
const RelyingParty = require('../src/RelyingParty')
const AuthenticationRequest = require('../src/AuthenticationRequest')
const AuthenticationResponse = require('../src/AuthenticationResponse')

/**
 * Tests
 */
describe('RelyingParty', () => {
  const providerUrl = 'https://example.com'
  const providerConfig = require('./resources/example.com/openid-configuration.json')
  const providerJwks = require('./resources/example.com/jwks.json')
  const rpRegistration = require('./resources/example.com/registration.json')
  const rpProviderConfig = require('./resources/example.com/rp-provider-config.json')

  afterEach(() => {
    nock.cleanAll()
  })

  describe('from', () => {
    it('should reject with invalid argument', () => {
      return RelyingParty.from({ provider: {} })
        .should.be.rejectedWith(/Provider url is required/)
    })

    it('should reject if provider config is absent', () => {
      const options = {
        provider: { url: providerUrl }
      }

      return RelyingParty.from(options)
        .should.be.rejectedWith(/OpenID Configuration is not initialized/)
    })

    it('should request JWK Set if missing from argument', async () => {
      const jwkRequest = nock(providerUrl).get('/jwks')
        .reply(200, providerJwks)

      const options = {
        provider: {
          url: providerUrl,
          configuration: rpProviderConfig
        }
      }

      const rp = await RelyingParty.from(options)
      expect(rp.provider.jwks.keys[0].alg).to.equal('RS256')
      expect(jwkRequest.isDone()).to.be.true()
    })

    it('should import JWK Set if defined in argument', () => {
      const jwkRequest = nock(providerUrl).get('/jwks').reply(200, providerJwks)

      const options = {
        provider: {
          url: providerUrl,
          configuration: rpProviderConfig,
          jwks: providerJwks
        }
      }

      return RelyingParty.from(options)
        .then(rp => {
          expect(rp.provider.jwks.keys[0].alg).to.equal('RS256')
          // nock request should not have been made
          expect(jwkRequest.isDone()).to.be.false()
        })
    })
  })

  describe('static register', () => {
    const registrationOptions = {}
    const options = {}

    beforeEach(() => {
      nock(providerUrl).get('/.well-known/openid-configuration')
        .reply(200, providerConfig)
      nock(providerUrl).get('/jwks')
        .reply(200, providerJwks)
      nock(providerUrl).post('/register')
        .reply(201, rpRegistration)
    })

    it('should resolve a RelyingParty instance', () => {
      return RelyingParty.register(providerUrl, registrationOptions, options)
        .then(rp => {
          expect(rp).to.be.instanceof(RelyingParty)
        })
    })

    it('should request provider OpenID configuration', () => {
      return RelyingParty.register(providerUrl, registrationOptions, options)
        .then(rp => {
          const providerConfig = rp.provider.configuration

          expect(providerConfig).to.exist()
          expect(providerConfig.registration_endpoint)
            .to.equal('https://example.com/register')
        })
    })

    it('should import provider JWK Set', () => {
      return RelyingParty.register(providerUrl, registrationOptions, options)
        .then(rp => {
          const providerJwks = rp.provider.jwks

          expect(providerJwks).to.exist()
          expect(providerJwks.keys[0].alg).to.equal('RS256')
        })
    })

    it('should register a client', () => {
      return RelyingParty.register(providerUrl, registrationOptions, options)
        .then(rp => {
          expect(rp.registration).to.eql(rpRegistration)
        })
    })
  })

  describe('discover', () => {
    beforeEach(() => {
      nock(providerUrl).get('/.well-known/openid-configuration')
        .reply(200, providerConfig)
    })

    it('should reject with missing provider url (issuer)', () => {
      const rp = new RelyingParty({ provider: {} })

      return rp.discover().should.be.rejectedWith(/RelyingParty provider must define "url"/)
    })

    it('should resolve and set provider OpenID Configuration', () => {
      const rp = new RelyingParty({ provider: { url: providerUrl } })

      return rp.discover()
        .then(() => {
          expect(rp.provider.configuration).to.eql(providerConfig)
        })
    })

    it('should reject on an http error', done => {
      nock('https://notfound').get('/.well-known/openid-configuration')
        .reply(404)

      const rp = new RelyingParty({ provider: { url: 'https://notfound' } })

      rp.discover()
        .catch(err => {
          expect(err.message)
            .to.match(/Error fetching openid configuration: 404 Not Found/)
          done()
        })
    })
  })

  describe('jwks', () => {
    beforeEach(() => {
      nock(providerUrl).get('/jwks').reply(200, providerJwks)
    })

    it('should reject with missing OpenID Configuration', () => {
      const rp = new RelyingParty({ provider: {} })

      return rp.jwks().should.be.rejectedWith(/OpenID Configuration is not initialized/)
    })

    it('should reject with missing jwks uri', () => {
      const rp = new RelyingParty({ provider: { configuration: {} } })

      return rp.jwks().should.be.rejectedWith(/OpenID Configuration is missing jwks_uri/)
    })

    it('should import and set provider JWK Set', () => {
      const provider = {
        url: providerUrl,
        configuration: { jwks_uri: providerUrl + '/jwks' }
      }
      const rp = new RelyingParty({ provider })

      return rp.jwks()
        .then(() => {
          expect(rp.provider).to.have.property('jwks')
        })
    })

    it('should resolve JWK Set', () => {
      const provider = {
        url: providerUrl,
        configuration: { jwks_uri: providerUrl + '/jwks' }
      }
      const rp = new RelyingParty({ provider })

      return rp.jwks()
        .then(jwks => {
          expect(jwks.keys[0].alg).to.equal('RS256')
        })
    })

    it('should reject on http error', done => {
      const providerUrl = 'https://notfound'

      nock(providerUrl).get('/jwks').reply(404)

      const provider = {
        url: providerUrl,
        configuration: { jwks_uri: providerUrl + '/jwks' }
      }
      const rp = new RelyingParty({ provider })

      rp.jwks()
        .catch(err => {
          expect(err.message).to.match(/Error resolving provider keys/)
          done()
        })
    })
  })

  describe('logoutRequest', () => {
    it('should error on missing OpenID Configuration', () => {
      const rp = new RelyingParty()
      const logoutRequest = rp.logoutRequest.bind(rp)

      logoutRequest.should.throw(/OpenID Configuration is not initialized/)
    })

    it('should return null on missing end_session_endpoint', () => {
      const options = {
        provider: {
          configuration: { issuer: 'https://forge.anvil.io' }
        }
      }
      const rp = new RelyingParty(options)

      expect(rp.logoutRequest()).to.be.null()
    })

    it('should return end_session_endpoint if no other params given', () => {
      const options = {
        provider: {
          configuration: {
            end_session_endpoint: 'https://example.com/logout'
          }
        }
      }
      const rp = new RelyingParty(options)

      expect(rp.logoutRequest()).to.equal('https://example.com/logout')
    })

    it('should compose logout request params into url', () => {
      const rpOptions = {
        provider: {
          configuration: {
            end_session_endpoint: 'https://example.com/logout'
          }
        }
      }
      const rp = new RelyingParty(rpOptions)

      const options = {
        id_token_hint: 't0ken',
        post_logout_redirect_uri: 'https://app.com/goodbye',
        state: '$tate'
      }

      const expectedLogoutUrl = 'https://example.com/logout?id_token_hint=t0ken&post_logout_redirect_uri=https%3A%2F%2Fapp.com%2Fgoodbye&state=%24tate'

      expect(rp.logoutRequest(options)).to.equal(expectedLogoutUrl)
    })
  })

  describe('logout', () => {
    it('should reject with missing OpenID Configuration', () => {
      const rp = new RelyingParty()

      return rp.logout().should.be.rejectedWith(/OpenID Configuration is not initialized/)
    })

    it('should return undefined when no end_session_endpoint exists', () => {
      const options = {
        provider: {
          configuration: { issuer: 'https://forge.anvil.io' }
        }
      }
      const rp = new RelyingParty(options)

      return rp.logout()
        .then(response => {
          expect((response === undefined).should.be.true())
        })
    })

    it('should make a request to the end_session_endpoint', () => {
      const logoutRequest = nock(providerUrl).get('/logout').reply(200)

      const provider = {
        url: providerUrl,
        configuration: rpProviderConfig
      }
      const rp = new RelyingParty({ provider, store: {} })

      return rp.logout()
        .then(() => {
          expect(logoutRequest.isDone()).to.be.true()
        })
    })

    it('should reject on http error', done => {
      const providerUrl = 'https://notfound'

      nock(providerUrl).get('/logout').reply(404)

      const provider = {
        url: providerUrl,
        configuration: {
          end_session_endpoint: 'https://notfound/logout'
        }
      }
      const rp = new RelyingParty({ provider })

      rp.logout()
        .catch(err => {
          expect(err.message).to.match(/Error logging out: 404 Not Found/)
          done()
        })
    })
  })

  describe('register', () => {
    beforeEach(() => {
      nock(providerUrl).get('/.well-known/openid-configuration')
        .reply(200, providerConfig)
      nock(providerUrl).get('/jwks')
        .reply(200, providerJwks)
      nock(providerUrl).post('/register')
        .reply(201, rpRegistration)
    })

    it('should reject with missing OpenID Configuration', () => {
      const options = { provider: {} }
      const rp = new RelyingParty(options)

      return rp.register().should.be.rejectedWith(/OpenID Configuration is not initialized/)
    })

    it('should reject with missing registration endpoint', () => {
      const options = {
        provider: {
          configuration: { issuer: providerUrl }
        },
        store: {}
      }
      const rp = new RelyingParty(options)

      return rp.register().should.be.rejectedWith(/OpenID Configuration is missing registration_endpoint/)
    })

    it('should resolve client registration', () => {
      const options = {
        provider: {
          configuration: {
            issuer: providerUrl,
            registration_endpoint: 'https://example.com/register'
          }
        }
      }
      const rp = new RelyingParty(options)

      return rp.register()
        .then(response => {
          expect(response).to.eql(rpRegistration)
        })
    })

    it('should set client registration', () => {
      const options = {
        provider: {
          configuration: {
            issuer: providerUrl,
            registration_endpoint: 'https://example.com/register'
          }
        }
      }
      const rp = new RelyingParty(options)

      return rp.register()
        .then(() => {
          expect(rp.registration).to.eql(rpRegistration)
        })
    })

    it('should reject on an http error', done => {
      nock('https://notfound').post('/register').reply(404)

      const options = {
        provider: {
          configuration: {
            issuer: 'https://notfound',
            registration_endpoint: 'https://notfound/register'
          }
        }
      }
      const rp = new RelyingParty(options)

      rp.register()
        .catch(err => {
          expect(err.message).to.match(/Error registering client: 404 Not Found/)
          done()
        })
    })
  })

  describe('userinfo', () => {
    it('should reject with missing OpenID Configuration', () => {
      const options = { provider: {} }
      const rp = new RelyingParty(options)

      return rp.userinfo().should.be.rejectedWith(/OpenID Configuration is not initialized/)
    })

    it('should reject with missing userinfo endpoint', () => {
      const options = {
        provider: {
          configuration: { issuer: 'https://forge.anvil.io' }
        }
      }
      const rp = new RelyingParty(options)

      return rp.userinfo().should.be.rejectedWith(/OpenID Configuration is missing userinfo_endpoint/)
    })

    it('should reject with missing access token', () => {
      const options = {
        provider: { configuration: rpProviderConfig },
        store: {}
      }
      const rp = new RelyingParty(options)

      return rp.userinfo()
        .should.be.rejectedWith(/Missing access token./)
    })

    it('should resolve parsed JSON response', () => {
      const userinfo = { sub: 'user123' }
      const userInfoReq = nock(providerUrl).get('/userinfo')
        .reply(200, userinfo)

      const options = {
        provider: { configuration: rpProviderConfig },
        store: { access_token: '1234' }
      }
      const rp = new RelyingParty(options)

      return rp.userinfo()
        .then(res => {
          expect(res).to.eql(userinfo)
          expect(userInfoReq.isDone()).to.be.true()
        })
    })

    it('should reject on an http error', done => {
      nock('https://notfound').get('/userinfo').reply(404)

      const options = {
        provider: {
          configuration: {
            issuer: 'https://notfound',
            userinfo_endpoint: 'https://notfound/userinfo'
          }
        },
        store: { access_token: '1234' }
      }
      const rp = new RelyingParty(options)

      rp.userinfo()
        .catch(err => {
          expect(err.message).to.match(/Error fetching userinfo: 404 Not Found/)
          done()
        })
    })
  })

  describe('serialize', () => {
    it('should return a JSON serialization', () => {
      const rp = new RelyingParty({})

      expect(rp.serialize()).to.equal('{"provider":{},"defaults":{"popToken":false,"authenticate":{"response_type":"id_token token","display":"page","scope":["openid"]}},"registration":{},"store":{}}')
    })
  })

  describe('createRequest', () => {
    after(() => {
      AuthenticationRequest.create.restore()
    })

    it('should create an AuthenticationRequest instance', () => {
      const request = {}
      sinon.stub(AuthenticationRequest, 'create').resolves(request)

      const store = {}
      const rp = new RelyingParty({ store })

      const options = {}

      return rp.createRequest(options)
        .then(res => {
          expect(res).to.equal(request)
          expect(AuthenticationRequest.create).to.have.been
            .calledWith(rp, options, store)
        })
    })
  })

  describe('validateResponse', () => {
    after(() => {
      AuthenticationResponse.validateResponse.restore()
      AuthenticationResponse.parseResponse.restore()
    })

    it('should create an AuthenticationResponse instance', () => {
      const session = {}
      sinon.stub(AuthenticationResponse, 'validateResponse').resolves(session)

      const store = {}
      const rp = new RelyingParty({ store })

      const mode = 'query'
      const params = {}
      sinon.stub(AuthenticationResponse, 'parseResponse').resolves({ mode, params })

      const uri = 'https://app.example.com/callback'

      return rp.validateResponse(uri)
        .then(res => {
          expect(res).to.equal(session)
          expect(AuthenticationResponse.validateResponse).to.have.been.called()
        })
    })
  })
})
