/**
 * Dependencies
 */
const assert = require('assert')
const crypto = require('./crypto')
const { encode: base64urlEncode } = require('base64url-universal')
const { JWT } = require('@solid/jose')
const FormUrlEncoded = require('./FormUrlEncoded')
const { IdGenerator } = require('bnid')

/**
 * Authentication Request
 */
class AuthenticationRequest {
  /**
   * create
   *
   * @description
   * Create a new authentication request with generated state and nonce,
   * validate presence of required parameters, serialize the request data and
   * persist it to the session, and return a promise for an authentication
   * request URI.
   *
   * @param {RelyingParty} rp – instance of RelyingParty
   * @param {object} options - optional request parameters
   * @param {object} session – reference to localStorage or other session object
   *
   * @returns {Promise}
   */
  static async create (rp, options, session) {
    const { provider, defaults, registration } = rp
    let params

    // validate presence of OP configuration, RP client registration,
    // and default parameters
    assert(provider.configuration,
      'RelyingParty provider OpenID Configuration is missing')

    assert(defaults.authenticate,
      'RelyingParty default authentication parameters are missing')

    assert(registration,
      'RelyingParty client registration is missing')

    // define basic elements of the request
    const issuer = provider.configuration.issuer
    const endpoint = provider.configuration.authorization_endpoint
    const client = { client_id: registration.client_id }
    params = Object.assign(defaults.authenticate, client, options)

    // validate presence of required configuration and parameters
    assert(issuer,
      'Missing issuer in provider OpenID Configuration')

    assert(endpoint,
      'Missing authorization_endpoint in provider OpenID Configuration')

    assert(params.scope,
      'Missing scope parameter in authentication request')

    assert(params.response_type,
      'Missing response_type parameter in authentication request')

    assert(params.client_id,
      'Missing client_id parameter in authentication request')

    assert(params.redirect_uri,
      'Missing redirect_uri parameter in authentication request')

    // generate code_verifier random octets for PKCE
    // @see https://tools.ietf.org/html/rfc7636
    const generator = new IdGenerator({ bitLength: 256 })
    const codeVerifier = base64urlEncode(await generator.generate())
    // store verifier, for future use with token endpoint
    params.code_verifier = codeVerifier

    // generate state and nonce random octets
    params.state = Array.from(crypto.getRandomValues(new Uint8Array(16)))
    params.nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)))

    // hash the state and nonce parameter values
    const digests = await Promise.all([
      crypto.subtle.digest({ name: 'SHA-256' }, new Uint8Array(params.state)),
      crypto.subtle.digest({ name: 'SHA-256' }, new Uint8Array(params.nonce))
    ])

    // serialize the request with original values, store in session by
    // encoded state param, and replace state/nonce octets with encoded
    // digests
    const state = base64urlEncode(new Uint8Array(digests[0]))
    const nonce = base64urlEncode(new Uint8Array(digests[1]))
    const key = `${issuer}/requestHistory/${state}`

    // store the request params for response validation
    // with serialized octet values for state and nonce
    session[key] = JSON.stringify(params)

    // replace state and nonce octets with base64url encoded digests
    params.state = state
    params.nonce = nonce

    // code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
    const encoder = new TextEncoder()
    const challengeDigest = await crypto.subtle.digest(
      { name: 'SHA-256' }, encoder.encode(codeVerifier)
    )
    params.code_challenge = base64urlEncode(new Uint8Array(challengeDigest))
    params.code_challenge_method = 'S256'

    const sessionKeys = await AuthenticationRequest.generateSessionKeys()
    await AuthenticationRequest.storeSessionKeys(sessionKeys, params, session)

    // optionally encode a JWT with the request parameters
    // and replace params with `{ request: <jwt> }
    if (provider.configuration.request_parameter_supported) {
      params = await AuthenticationRequest.encodeRequestParams(params)
    }

    // render the request URI and terminate the algorithm
    const url = new URL(endpoint)
    url.search = FormUrlEncoded.encode(params)

    return url.href
  }

  static async generateSessionKeys () {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: 'SHA-256' }
      },
      true,
      ['sign', 'verify']
    )
    // returns a keypair object
    const jwkPair = await Promise.all([
      crypto.subtle.exportKey('jwk', keyPair.publicKey),
      crypto.subtle.exportKey('jwk', keyPair.privateKey)
    ])
    const [publicJwk, privateJwk] = jwkPair

    return { public: publicJwk, private: privateJwk }
  }

  static storeSessionKeys (sessionKeys, params, session) {
    // store the private one in session, public one goes into params
    session['oidc.session.privateKey'] = JSON.stringify(sessionKeys.private)
    if (sessionKeys.public) {
      params.key = sessionKeys.public
    }
  }

  static async encodeRequestParams (params) {
    const excludeParams = ['scope', 'client_id', 'response_type', 'state']

    const keysToEncode = Object.keys(params).filter(key => !excludeParams.includes(key))

    const payload = {}

    keysToEncode.forEach(key => {
      payload[key] = params[key]
    })

    const requestParamJwt = new JWT({
      header: { alg: 'none' },
      payload
    })

    const requestParamCompact = await requestParamJwt.encode()
    const newParams = {
      scope: params.scope,
      client_id: params.client_id,
      response_type: params.response_type,
      request: requestParamCompact,
      state: params.state
    }

    return newParams
  }
}

/**
 * Export
 */
module.exports = AuthenticationRequest
