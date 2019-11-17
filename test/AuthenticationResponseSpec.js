'use strict'

/**
 * Test dependencies
 */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
const nock = require('nock')
const sinon = require('sinon')

/**
 * Assertions
 */
chai.should()
chai.use(require('sinon-chai'))
chai.use(chaiAsPromised)
chai.use(require('dirty-chai'))
let expect = chai.expect

/**
 * Code under test
 */
const {JWT, JWKSet} = require('@solid/jose')
const IDToken = require('../src/IDToken')
const AuthenticationResponse = require('../src/AuthenticationResponse')
const { getPublicKey, getPrivateKey } = require('./keys')

/**
 * Tests
 */
describe('AuthenticationResponse', () => {
  const providerJwks = require('./resources/example.com/jwks.json')

  let publicKey, privateKey

  before(async () => {

  })

  afterEach(() => {
    nock.cleanAll()
  })

  /**
   * parseResponse
   */
  describe('parseResponse', () => {
    it('should throw with redirect and body', () => {
      expect(() => {
        AuthenticationResponse.parseResponse({
          redirect: 'https://example.com/callback?code=1234',
          body: 'code=1234'
        })
      }).to.throw('Invalid response mode')
    })

    it('should throw with query and fragment', () => {
      expect(() => {
        AuthenticationResponse.parseResponse({
          redirect: 'https://example.com/callback?code=1234#code=1234'
        })
      }).to.throw('Invalid response mode')
    })

    it('should throw without query and fragment', () => {
      expect(() => {
        AuthenticationResponse.parseResponse({
          redirect: 'https://example.com/callback'
        })
      }).to.throw('Invalid response mode')
    })

    it('should parse query response', () => {
      const response = { redirect: 'https://example.com/callback?code=1234' }
      const { params, mode } = AuthenticationResponse.parseResponse(response)
      params.should.eql({ code: '1234' })
      mode.should.equal('query')
    })

    it('should parse fragment response', () => {
      const response = { redirect: 'https://example.com/callback#code=1234' }
      const { params, mode } = AuthenticationResponse.parseResponse(response)
      params.should.eql({ code: '1234' })
      mode.should.equal('fragment')
    })

    it('should parse form post response', () => {
      const response = { body: 'code=1234' }
      const { params, mode } = AuthenticationResponse.parseResponse(response)
      params.should.eql({ code: '1234' })
      mode.should.equal('form_post')
    })
  })

  /**
   * matchRequest
   */
  describe('matchRequest', () => {
    let response

    beforeEach(() => {
      response = {
        rp: {
          provider: {
            configuration: {
              issuer: 'https://forge.anvil.io'
            }
          }
        },
        params: {
          state: '1234'
        },
        session: {
          'https://forge.anvil.io/requestHistory/1234': JSON.stringify({
            scope: 'openid'
          })
        }
      }
    })

    it('should throw with missing state parameter', () => {
      expect(() => {
        delete response.params.state
        AuthenticationResponse.matchRequest(response)
      }).to.throw('Missing state parameter in authentication response')
    })

    it('should throw with mismatching state parameter', () => {
      expect(() => {
        response.params.state = '1235'
        AuthenticationResponse.matchRequest(response)
      }).to.throw('Mismatching state parameter in authentication response')
    })

    it('should deserialize the matched request', () => {
      const request = AuthenticationResponse.matchRequest(response)
      request.should.eql({ scope: 'openid' })
    })
  })

  /**
   * validateStateParam
   */
  describe('validateStateParam', () => {
    let response

    beforeEach(() => {
      response = {
        request: {
          state: [234, 32, 145, 21]
        },
        params: {
          state: 'QRGTj6K-tdhEps0rgQ6S0h_UQkIij3sy_Cx8VGR0EIw'
        }
      }
    })

    it('should reject with mismatching state parameter', () => {
      response.request.state.push(123)
      return AuthenticationResponse.validateStateParam(response)
        .should.be
        .rejectedWith('Mismatching state parameter in authentication response')
    })
  })

  /**
   * errorResponse
   */
  describe('errorResponse', () => {
    it('should throw an error if error param is present', done => {
      const errorParams = {
        error: 'access_denied',
        error_description: 'Access denied',
        error_uri: 'https://example.com/123',
        state: '$tate'
      }
      const response = new AuthenticationResponse({ params: {...errorParams} })
      try {
        AuthenticationResponse.errorResponse(response)
      } catch (error) {
        error.message.should
          .equal('AuthenticationResponse error: access_denied')
        error.info.should.eql(errorParams)
        done()
      }
    })
  })

  /**
   * validateResponseMode
   */
  describe('validateResponseMode', () => {
    let response

    beforeEach(() => {
      response = {
        request: { response_type: 'id_token token' },
        mode: 'fragment'
      }
    })

    it('should throw with `query` mode for non-"code" response type', () => {
      expect(() => {
        response.mode = 'query'
        AuthenticationResponse.validateResponseMode(response)
      }).to.throw('Invalid response mode')
    })
  })

  /**
   * validateResponseParams
   */
  describe('validateResponseParams', () => {
    let response

    beforeEach(() => {
      response = {
        request: { response_type: 'code id_token token' },
        params: {
          code: 'c0d3',
          id_token: 'jwt',
          access_token: 'r4nd0m',
          token_type: 'bearer'
        }
      }
    })

    it('should throw with missing authorization code', () => {
      expect(() => {
        delete response.params.code
        AuthenticationResponse.validateResponseParams(response)
      }).to.throw('Missing authorization code in authentication response')
    })

    it('should throw with missing id_token', () => {
      expect(() => {
        delete response.params.id_token
        AuthenticationResponse.validateResponseParams(response)
      }).to.throw('Missing id_token in authentication response')
    })

    it('should throw with missing access_token', () => {
      expect(() => {
        delete response.params.access_token
        AuthenticationResponse.validateResponseParams(response)
      }).to.throw('Missing access_token in authentication response')
    })

    it('should throw with missing token_type', () => {
      expect(() => {
        delete response.params.token_type
        AuthenticationResponse.validateResponseParams(response)
      }).to.throw('Missing token_type in authentication response')
    })
  })

  /**
   * exchangeAuthorizationCode
   */
  describe('exchangeAuthorizationCode', () => {
    const providerUrl = 'https://example.com'
    const providerConfig = require('./resources/example.com/openid-configuration.json')

    const tokenResponse = {
      'access_token': '4ccesst0ken',
      'token_type': 'bearer',
      'id_token': '1dt0ken'
    }

    let response

    beforeEach(() => {
      response = {
        request: {
          'response_type': 'code',
          'redirect_uri': 'https://app.example.com/callback'
        },
        params: {
          code: 'c0d3',
          'id_token': 'jwt',
          'access_token': 'client4ccess',
          'token_type': 'bearer'
        },
        rp: {
          provider: { configuration: providerConfig },
          registration: {
            'client_id': 'client123',
            'client_secret': 's33kret'
          }
        }
      }
    })

    it('should not exchange code unless response type is exactly `code`', async () => {
      const tokenRequest = nock(providerUrl).post('/token')
        .reply(200)

      response.request['response_type'] = 'code id_token token'

      const result = await AuthenticationResponse.exchangeAuthorizationCode(response)
      expect(tokenRequest.isDone()).to.be.false()
      expect(result).to.be.undefined()
    })

    it('should exchange the code if response type is exactly `code`')

    it('should throw with a public client', () => {
      delete response.rp.registration['client_secret']

      return AuthenticationResponse.exchangeAuthorizationCode(response)
        .should.be.rejectedWith(/is not a confidential client/)
    })

    it('should set Content-Type header', () => {
      let requiredHeaders = {
        'content-type': 'application/x-www-form-urlencoded'
      }
      let tokenRequest = nock(providerUrl, { reqheaders: requiredHeaders })
        .post('/token')
        .reply(200, tokenResponse)

      return AuthenticationResponse.exchangeAuthorizationCode(response)
        .then(() => {
          expect(tokenRequest.isDone()).to.be.true()
        })
    })

    it('should include grant_type in the request', () => {
      let tokenRequest = nock(providerUrl)
        .post('/token', /grant_type=authorization_code/)  // required body regex
        .reply(200, tokenResponse)

      return AuthenticationResponse.exchangeAuthorizationCode(response)
        .then(() => {
          expect(tokenRequest.isDone()).to.be.true()
        })
    })

    it('should include code in the request', () => {
      let tokenRequest = nock(providerUrl)
        .post('/token', /code=c0d3/)  // required body regex
        .reply(200, tokenResponse)

      return AuthenticationResponse.exchangeAuthorizationCode(response)
        .then(() => {
          expect(tokenRequest.isDone()).to.be.true()
        })
    })

    it('should include redirect_uri in the request', () => {
      let tokenRequest = nock(providerUrl)
        .post('/token', /redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback/)
        .reply(200, tokenResponse)

      return AuthenticationResponse.exchangeAuthorizationCode(response)
        .then(() => {
          expect(tokenRequest.isDone()).to.be.true()
        })
    })

    it('should authenticate client with HTTP Basic credentials', async () => {
      const requiredHeaders = {
        'authorization': 'Basic Y2xpZW50MTIzOnMzM2tyZXQ='
      }
      const tokenRequest = nock(providerUrl, { reqheaders: requiredHeaders })
        .post('/token')
        .reply(200, tokenResponse)

      await AuthenticationResponse.exchangeAuthorizationCode(response)
      expect(tokenRequest.isDone()).to.be.true()
    })

    it('should authenticate client with form POST credentials', () => {
      response.rp.registration['token_endpoint_auth_method'] = 'client_secret_post'

      let tokenRequest = nock(providerUrl)
        .post('/token', /client_id=client123&client_secret=s33kret/)
        .reply(200, tokenResponse)

      return AuthenticationResponse.exchangeAuthorizationCode(response)
        .then(() => {
          expect(tokenRequest.isDone()).to.be.true()
        })
    })

    it('should authenticate client with JWT')

    it('should validate the presence of token_type in token response', () => {
      let tokenResponse = {
        'access_token': '4ccesst0ken',
        'id_token': '1dt0ken'
      }

      let tokenRequest = nock(providerUrl)
        .post('/token')
        .reply(200, tokenResponse)

      return AuthenticationResponse.exchangeAuthorizationCode(response)
        .should.be.rejectedWith('Missing token_type in token response.')
    })

    it('should include token response in response params')

    it('should reject on an http error', done => {
      let providerUrl = 'https://notfound'

      nock(providerUrl).post('/token').reply(404)

      response.rp.provider.configuration.url = providerUrl
      response.rp.provider.configuration['token_endpoint'] = providerUrl + '/token'

      AuthenticationResponse.exchangeAuthorizationCode(response)
        .catch(err => {
          expect(err.message)
            .to.match(/Error exchanging authorization code: 404 Not Found/)
          done()
        })
    })
  })

  /**
   * validateIDToken
   */

  /**
   * decodeIDToken
   */
  describe('decodeIDToken', () => {
    let jwt

    beforeEach(() => {
      jwt = 'eyJhbGciOiJSUzI1NiIsImtpZCI6InI0bmQwbWJ5dDNzIn0.eyJpc3MiOiJodHRwczovL2ZvcmdlLmFudmlsLmlvIn0.FMer-lRR4Q4BVivMc9sl-jF3c-QWEenlH2pcW9oXTsiPRSEzc7lgPEryuXTimoToSKwWFgVpnjXKnmBaTaPVLpuRUMwGUeIUdQu0bQC-XEo-TKlwlqtUgelQcF2viEQwxU04UQaXWBh9ZDTIOutfXcjyhEPiMfCFLxT_aotR0zipmAi825lF1qBmxKrCv4c_9_46ACuaeuET6t0XvcAMDf3fjkEdw_0KPN2wnAlp2AwPP05D8Nwn8NqDAlljdN7bjnO99uJvhNWbvZgBYfhNXkMeDVJcukv0j3Cz6LCgedbXdX0rzJv_4qkO6l-LU9QeK1s0kwHfRUIWoa0TLJ4FtQ'
    })

    it('should decode id_token response parameter', () => {
      const decoded = AuthenticationResponse.decodeIDToken(jwt)
      decoded.should.be.instanceof(JWT)
    })

    it('should throw an error on invalid id_token', () => {
      expect(() => {
        AuthenticationResponse.decodeIDToken('inva1id')
      }).to.throw('Error decoding ID Token')
    })
  })

  /**
   * validateIssuer
   */
  describe('validateIssuer', () => {
    let response

    beforeEach(() => {
      response = {
        rp: {
          provider: {
            configuration: {
              issuer: 'https://forge.anvil.io'
            }
          }
        },
        decoded: {
          payload: {
            iss: 'https://forge.anvil.io'
          }
        }
      }
    })

    it('should throw with mismatching issuer', () => {
      expect(() => {
        response.decoded.payload.iss = 'https://example.com'
        AuthenticationResponse.validateIssuer(response)
      }).to.throw('Mismatching issuer in ID Token')
    })
  })

  /**
   * validateAudience
   */
  describe('validateAudience', () => {
    let response

    beforeEach(() => {
      response = {
        rp: {
          registration: {
            client_id: 'uuid'
          }
        },
        decoded: {
          payload: {
            aud: 'uuid'
          }
        }
      }
    })

    it('should throw with mismatching string audience', () => {
      expect(() => {
        response.decoded.payload.aud = 'other'
        AuthenticationResponse.validateAudience(response)
      }).to.throw('Mismatching audience in id_token')
    })

    it('should throw with missing client in audience list', () => {
      expect(() => {
        response.decoded.payload.aud = ['other']
        AuthenticationResponse.validateAudience(response)
      }).to.throw('Mismatching audience in id_token')
    })

    it('should throw with missing authorized party', () => {
      expect(() => {
        response.decoded.payload.aud = ['other', 'uuid']
        AuthenticationResponse.validateAudience(response)
      }).to.throw('Missing azp claim in id_token')
    })

    it('should throw with mismatching authorized party', () => {
      expect(() => {
        response.decoded.payload.aud = ['other', 'uuid']
        response.decoded.payload.azp = 'wrong'
        AuthenticationResponse.validateAudience(response)
      }).to.throw('Mismatching azp claim in id_token')
    })
  })

  /**
   * resolveKeys
   */
  describe('resolveKeys', () => {
    let response

    beforeEach(() => {
      response = {
        rp: {
          provider: {},
          jwks: sinon.stub().resolves(providerJwks)
        },
        decoded: {
          resolveKeys: sinon.stub().withArgs(providerJwks).returns(true)
        }
      }
    })

    it('should request keys from provider if necessary', async () => {
      await AuthenticationResponse.resolveKeys(response)
      expect(response.rp.jwks).to.have.been.called()
    })

    it('should use already imported keys if available', async () => {
      const jwks = await JWKSet.importKeys(providerJwks)
      response.rp.provider.jwks = jwks
      await AuthenticationResponse.resolveKeys(response)
      expect(response.rp.jwks).to.not.have.been.called()
    })

    it('should throw an error if token resolve keys operation fails', async () => {
      response.decoded.resolveKeys = sinon.stub()
        .withArgs(providerJwks).returns(false)

      let error
      try {
        await AuthenticationResponse.resolveKeys(response)
      } catch (thrownError) {
        error = thrownError
      }
      expect(error).to.exist()
      expect(error.message).to.match(/Cannot resolve signing key for ID Token/)
    })
  })

  /**
   * verifySignature
   */
  describe('verifySignature', () => {
    let response

    beforeEach(async () => {
      const token = new IDToken({
        header: {
          alg: 'RS256',
          kid: 'r4nd0mbyt3s'
        },
        payload: {
          iss: 'https://forge.anvil.io',
          sub: 'uid',
          aud: 'cid',
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000),
          nonce: 'n0nc3'
        },
        key: await getPrivateKey()
      })

      const jwt = await token.encode()
      const decoded = IDToken.decode(jwt)
      decoded.key = await getPublicKey()

      response = {
        decoded,
        rp: {
          registration: {
            id_token_signed_response_alg: 'RS256'
          }
        }
      }
    })

    it('should throw with mismatching signing algorithm', async () => {
      response.rp.registration['id_token_signed_response_alg'] = 'HS256'
      let error
      try {
        await AuthenticationResponse.verifySignature(response)
      } catch (thrown) {
        error = thrown
      }
      expect(error).to.exist()
      expect(error.message).to.match(/Expected ID Token to be signed with HS256/)
    })

    it('should reject with invalid ID Token signature', () => {
      response.decoded.signature += 'wrong'
      return AuthenticationResponse.verifySignature(response)
        .should.be.rejectedWith('Invalid ID Token signature')
    })
  })

  /**
   * validateExpires
   */
  describe('validateExpires', () => {
    let response

    beforeEach(async () => {
      const token = new IDToken({
        header: {
          alg: 'RS256',
          kid: 'r4nd0mbyt3s'
        },
        payload: {
          iss: 'https://forge.anvil.io',
          sub: 'uid',
          aud: 'cid',
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000),
          nonce: 'n0nc3'
        },
        key: await getPrivateKey()
      })

      const jwt = await token.encode()
      const decoded = IDToken.decode(jwt)
      decoded.key = await getPublicKey()

      response = {
        decoded,
        rp: {
          registration: {
            id_token_signed_response_alg: 'RS256'
          }
        }
      }
    })

    it('should throw with expired ID Token', () => {
      expect(() => {
        response.decoded.payload.exp -= 7200
        AuthenticationResponse.validateExpires(response)
      }).to.throw('Expired ID Token')
    })
  })

  /**
   * verifyNonce
   */
  describe('verifyNonce', () => {
    let response

    beforeEach(async () => {
      const token = new IDToken({
        header: {
          alg: 'RS256',
          kid: 'r4nd0mbyt3s'
        },
        payload: {
          iss: 'https://forge.anvil.io',
          sub: 'uid',
          aud: 'cid',
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000),
          nonce: 'QRGTj6K-tdhEps0rgQ6S0h_UQkIij3sy_Cx8VGR0EIw'
        },
        key: await getPrivateKey()
      })

      const jwt = await token.encode()
      const decoded = IDToken.decode(jwt)
      decoded.key = await getPublicKey()

      response = {
        decoded,
        request: {
          nonce: [234, 32, 145, 21]
        }
      }
    })

    it('should throw with missing nonce claim', async () => {
      delete response.decoded.payload.nonce
      let error
      try {
        await AuthenticationResponse.verifyNonce(response)
      } catch (thrown) {
        error = thrown
      }
      expect(error).to.exist()
      expect(error.message).to.match(/Missing nonce in ID Token/)
    })

    it('should reject with mismatching nonce claim', () => {
      response.request.nonce.push(123)
      return AuthenticationResponse.verifyNonce(response)
        .should.be
        .rejectedWith('Mismatching nonce in ID Token')
    })
  })

  /**
   * validateAcr
   */

  /**
   * validateAccessTokenHash
   */

  /**
   * validateAuthorizationCodeHash
   */
})
