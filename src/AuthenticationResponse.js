/* eslint-disable camelcase */
/**
 * Dependencies
 */
const fetch = require('cross-fetch')
const assert = require('assert')
const crypto = require('./crypto')
const { encode: base64urlEncode } = require('base64url-universal')
const Headers = fetch.Headers // ? fetch.Headers : global.Headers
const FormUrlEncoded = require('./FormUrlEncoded')
const IDToken = require('./IDToken')
const Session = require('./Session')
const onHttpError = require('./onHttpError')
const HttpError = require('standard-http-error')
const { encode: base64encode } = require('universal-base64')

/**
 * AuthenticationResponse
 */
class AuthenticationResponse {
  /**
   * @param rp {RelyingParty}
   * @param [redirect] {string} req.query
   * @param [body] {string} req.body.text
   * @param session {Session|Storage} req.session or localStorage or similar
   * @param params {object} hashmap
   * @param mode {string} 'query'/'fragment'/'form_post',
   *   determined in `parseResponse()`
   */
  constructor ({ rp, redirect, body, session, mode, params = {} }) {
    this.rp = rp
    this.redirect = redirect
    this.body = body
    this.session = session
    this.mode = mode
    this.params = params
  }

  /**
   * validateResponse
   *
   * @description
   * Authentication response validation.
   *
   * @param {AuthenticationResponse} response
   *
   * @returns {Promise<Session>}
   */
  static async validateResponse (response) {
    // If response contains an error object, throw it
    this.errorResponse(response)

    response.request = this.matchRequest(response)

    await this.validateStateParam(response)
    this.validateResponseMode(response)
    this.validateResponseParams(response)

    const tokenResponse = await this.exchangeAuthorizationCode(response)
    if (tokenResponse) {
      // add access_token / id_token, if appropriate
      Object.assign(response.params, tokenResponse)
    }

    await this.validateIDToken(response)

    return Session.fromAuthResponse(response)
  }

  /**
   * parseResponse
   *
   * @param [redirect] {string} Redirect uri
   * @param [body] {object} Parsed request body
   *
   * @returns {{mode: string, params: object}}
   */
  static parseResponse ({ redirect, body }) {
    // response must be either a redirect uri or request body, but not both
    if ((redirect && body) || (!redirect && !body)) {
      throw new HttpError(400, 'Invalid response mode')
    }

    let params, mode

    // parse redirect uri
    if (redirect) {
      const url = new URL(redirect)
      const { search, hash } = url

      if ((search && hash) || (!search && !hash)) {
        throw new HttpError(400, 'Invalid response mode')
      }

      if (search) {
        params = FormUrlEncoded.decode(search.substring(1))
        mode = 'query'
      }

      if (hash) {
        params = FormUrlEncoded.decode(hash.substring(1))
        mode = 'fragment'
      }
    }

    // parse request form body
    if (body) {
      params = FormUrlEncoded.decode(body)
      mode = 'form_post'
    }

    return { params, mode }
  }

  /**
   * errorResponse
   *
   * @param {AuthenticationResponse} response
   *
   * @throws {Error} If response params include the OAuth2 'error' param,
   *   throws an error based on it.
   *
   * @returns {AuthenticationResponse} Chainable
   *
   * @todo Figure out HTTP status code (typically 400, 401 or 403)
   *   based on the OAuth2/OIDC `error` code, probably using an external library
   */
  static errorResponse (response) {
    const errorCode = response.params.error

    if (errorCode) {
      const errorParams = {}
      errorParams.error = errorCode
      errorParams.error_description = response.params.error_description
      errorParams.error_uri = response.params.error_uri
      errorParams.state = response.params.state

      const error = new Error(`AuthenticationResponse error: ${errorCode}`)
      error.info = errorParams
      throw error
    }

    return response
  }

  /**
   * matchRequest
   *
   * @param {object} response
   *
   * @returns {object} Original request object, loaded from storage by state
   */
  static matchRequest (response) {
    const { rp, params, session } = response
    const state = params.state
    const issuer = rp.provider.configuration.issuer

    if (!state) {
      throw new Error(
        'Missing state parameter in authentication response.')
    }

    const key = `${issuer}/requestHistory/${state}`
    const request = session[key]

    if (!request) {
      throw new Error(
        'Mismatching state parameter in authentication response.')
    }

    return JSON.parse(request)
  }

  /**
   * validateStateParam
   *
   * @param {object} response
   * @returns {Promise}
   */
  static async validateStateParam (response) {
    const octets = new Uint8Array(response.request.state)
    const encoded = response.params.state

    const digest = await crypto.subtle.digest({ name: 'SHA-256' }, octets)
    if (encoded !== base64urlEncode(new Uint8Array(digest))) {
      throw new Error(
        'Mismatching state parameter in authentication response.')
    }

    return response
  }

  /**
   * validateResponseMode
   *
   * @param {object} response
   */
  static validateResponseMode (response) {
    if (response.request.response_type !== 'code' && response.mode === 'query') {
      throw new Error('Invalid response mode.')
    }
  }

  /**
   * validateResponseParams
   *
   * @param {object} response
   */
  static validateResponseParams (response) {
    const { request, params } = response
    const expectedParams = request.response_type.split(' ')

    if (expectedParams.includes('code')) {
      assert(params.code,
        'Missing authorization code in authentication response')
      // TODO assert novelty of code
    }

    if (expectedParams.includes('id_token')) {
      assert(params.id_token,
        'Missing id_token in authentication response')
    }

    if (expectedParams.includes('token')) {
      assert(params.access_token,
        'Missing access_token in authentication response')

      assert(params.token_type,
        'Missing token_type in authentication response')
    }
  }

  /**
   * exchangeAuthorizationCode
   *
   * @param {object} response
   * @returns {undefined|{id_token:*, access_token:*, token_type:*}}
   */
  static async exchangeAuthorizationCode (response) {
    const { rp, params, request } = response
    const code = params.code

    // only exchange the authorization code when the response type is "code"
    if (!code || request.response_type !== 'code') {
      return
    }

    const { provider, registration } = rp
    const id = registration.client_id
    const secret = registration.client_secret

    // verify the client is not public
    if (!secret) {
      throw new Error(
        'Client cannot exchange authorization code because it is not a confidential client.')
    }

    // initialize token request arguments
    const endpoint = provider.configuration.token_endpoint
    const method = 'POST'

    // initialize headers
    const headers = new Headers({
      'Content-Type': 'application/x-www-form-urlencoded'
    })

    // initialize the token request parameters
    const bodyContents = {
      grant_type: 'authorization_code',
      code: code,
      code_verifier: response.request.code_verifier,
      redirect_uri: request.redirect_uri
    }

    // determine client authentication method
    const authMethod = registration.token_endpoint_auth_method ||
      'client_secret_basic'

    // client secret basic authentication
    if (authMethod === 'client_secret_basic') {
      const credentials = base64encode(`${id}:${secret}`)
      headers.set('Authorization', `Basic ${credentials}`)
    }

    // client secret post authentication
    if (authMethod === 'client_secret_post') {
      bodyContents.client_id = id
      bodyContents.client_secret = secret
    }

    const body = FormUrlEncoded.encode(bodyContents)

    // TODO
    // client_secret_jwt authentication
    // private_key_jwt

    // make the token request

    const tokenResponse = await fetch(endpoint, { method, headers, body })
      .then(onHttpError('Error exchanging authorization code'))

    const { access_token, token_type, id_token } = await tokenResponse.json()

    // assert(access_token, 'Missing access_token in token response')

    assert(token_type, 'Missing token_type in token response.')

    // assert(id_token, 'Missing id_token in token response')

    return { access_token, token_type, id_token }
  }

  /**
   * validateIDToken
   *
   * @param {AuthenticationResponse} response
   *
   * @returns {Promise}
   */
  static async validateIDToken (response) {
    const idToken = response.params.id_token
    // only validate the ID Token if present in the response
    if (!idToken) {
      return
    }

    // await this.decryptIDToken(response)
    response.decoded = this.decodeIDToken(idToken)

    this.validateIssuer(response)
    this.validateAudience(response)
    await this.resolveKeys(response)
    await this.verifySignature(response)
    this.validateExpires(response)
    await this.verifyNonce(response)

    // TODO
    // this.validateAcr()
    // this.validateAuthTime()
    // this.validateAccessTokenHash()
    // this.validateAuthorizationCodeHash()
  }

  /**
   * decryptIDToken
   *
   * @param {object} response
   * @returns {Promise}
   */
  static async decryptIDToken (response) {
    // TODO (not currently supported)
    return response
  }

  /**
   * decodeIDToken
   *
   * Note: If the `id_token` is not present in params, this method does not
   * get called (short-circuited in `validateIDToken()`).
   *
   * @param idToken {string}
   *
   * @returns {JWT}
   */
  static decodeIDToken (idToken) {
    let decoded
    try {
      decoded = IDToken.decode(idToken)
    } catch (decodeError) {
      const error = new HttpError(400, 'Error decoding ID Token')
      error.cause = decodeError
      error.info = { id_token: idToken }
      throw error
    }

    return decoded
  }

  /**
   * validateIssuer
   *
   * @param {object} response
   */
  static validateIssuer (response) {
    const configuration = response.rp.provider.configuration
    if (!response.decoded) {
      throw new Error('Cannot validate issuer - missing decoded ID Token.')
    }
    const payload = response.decoded.payload

    // validate issuer of token matches this relying party's provider
    if (payload.iss !== configuration.issuer) {
      throw new Error('Mismatching issuer in ID Token.')
    }

    return response
  }

  /**
   * validateAudience
   *
   * @param {object} response
   */
  static validateAudience (response) {
    const registration = response.rp.registration
    const { aud, azp } = response.decoded.payload

    // validate audience includes this relying party
    if (typeof aud === 'string' && aud !== registration.client_id) {
      throw new Error('Mismatching audience in id_token')
    }

    // validate audience includes this relying party
    if (Array.isArray(aud) && !aud.includes(registration.client_id)) {
      throw new Error('Mismatching audience in id_token')
    }

    // validate authorized party is present if required
    if (Array.isArray(aud) && !azp) {
      throw new Error('Missing azp claim in id_token')
    }

    // validate authorized party is this relying party
    if (azp && azp !== registration.client_id) {
      throw new Error('Mismatching azp claim in id_token')
    }
  }

  /**
   * resolveKeys
   * Validates that the provider keys resolve and match the jwk,
   * throws error otherwise.
   */
  static async resolveKeys (response) {
    const rp = response.rp
    const provider = rp.provider
    const decoded = response.decoded
    let jwks
    let isFreshJwks = false

    if (provider.jwks) {
      jwks = provider.jwks
    } else {
      isFreshJwks = true
      jwks = await rp.jwks()
    }

    if (decoded.resolveKeys(jwks)) {
      return
    }

    if (!isFreshJwks) {
      // The OP JWK Set cached by the RP may be stale due to key rotation by the OP.
      jwks = await rp.jwks()
      if (decoded.resolveKeys(jwks)) {
        return
      }
    }

    throw new Error('Cannot resolve signing key for ID Token.')
  }

  /**
   * verifySignature
   *
   * @param {object} response
   */
  static async verifySignature (response) {
    const alg = response.decoded.header.alg
    const registration = response.rp.registration
    const expectedAlgorithm = registration.id_token_signed_response_alg || 'RS256'

    // validate signing algorithm matches expectation
    if (alg !== expectedAlgorithm) {
      throw new Error(
        `Expected ID Token to be signed with ${expectedAlgorithm}`)
    }

    if (!(await response.decoded.verify())) {
      throw new Error('Invalid ID Token signature.')
    }
  }

  /**
   * validateExpires
   *
   * @param {object} response
   */
  static validateExpires (response) {
    const exp = response.decoded.payload.exp

    // validate expiration of token
    if (exp <= Math.floor(Date.now() / 1000)) {
      throw new Error('Expired ID Token.')
    }
  }

  /**
   * verifyNonce
   *
   * @param {object} response
   * @returns {Promise}
   */
  static async verifyNonce (response) {
    const octets = new Uint8Array(response.request.nonce)
    const nonce = response.decoded.payload.nonce

    if (!nonce) {
      throw new Error('Missing nonce in ID Token.')
    }

    const digest = await crypto.subtle.digest({ name: 'SHA-256' }, octets)
    if (nonce !== base64urlEncode(new Uint8Array(digest))) {
      throw new Error('Mismatching nonce in ID Token.')
    }
  }

  /**
   * validateAcr
   *
   * @param {object} response
   * @returns {object}
   */
  static validateAcr (response) {
    // TODO
    return response
  }

  /**
   * validateAuthTime
   *
   * @param {object} response
   * @returns {Promise}
   */
  static validateAuthTime (response) {
    // TODO
    return response
  }

  /**
   * validateAccessTokenHash
   *
   * @param {object} response
   * @returns {Promise}
   */
  static validateAccessTokenHash (response) {
    // TODO
    return response
  }

  /**
   * validateAuthorizationCodeHash
   *
   * @param {object} response
   * @returns {Promise}
   */
  static validateAuthorizationCodeHash (response) {
    // TODO
    return response
  }
}

/**
 * Export
 */
module.exports = AuthenticationResponse
