/* eslint-disable camelcase */
'use strict'
/**
 * Dependencies
 */
const fetch = require('cross-fetch')
const assert = require('assert')
const Headers = fetch.Headers // ? fetch.Headers : global.Headers
const { JWKSet } = require('@solid/jose')
const AuthenticationRequest = require('./AuthenticationRequest')
const AuthenticationResponse = require('./AuthenticationResponse')
const onHttpError = require('./onHttpError')
const FormUrlEncoded = require('./FormUrlEncoded')

/**
 * RelyingParty
 *
 * @class
 * Client interface for OpenID Connect Relying Party.
 *
 * @example
 *  let client = RelyingParty({
 *    provider: {
 *      name: 'Anvil Research, Inc.',
 *      url: 'https://forge.anvil.io'
 *      // configuration
 *      // jwks
 *    },
 *    defaults: {
 *      popToken: false,
 *      authenticate: {
 *        response_type: 'code',
 *        display: 'popup',
 *        scope: 'openid profile email'
 *      },
 *      register: {
 *        client_name: 'Example',
 *        client_uri: 'https://example.com',
 *        logo_uri: 'https://example.com/assets/logo.png',
 *        redirect_uris: ['https://app.example.com/callback'],
 *        response_types: ['code', 'code id_token token'],
 *        grant_types: ['authorization_code'],
 *        default_max_age: 7200,
 *        post_logout_redirect_uris: ['https://app.example.com']
 *      },
 *    },
 *    registration: {
 *      // if you have it saved somewhere
 *    },
 *    store: localStorage || req.session
 *  })
 *
 *  client.discover() => Promise
 *  client.jwks() => Promise
 *  client.authenticate()
 *  client.authenticateUri()
 *  client.validateResponse(uri) => Promise
 *  client.userinfo() => Promise
 *  client.logout()
 */
class RelyingParty {
  constructor ({ provider = {}, defaults, registration = {}, store = {} } = {}) {
    this.provider = provider
    this.defaults = defaults || {
      popToken: false,
      authenticate: {
        response_type: 'id_token token',
        display: 'page',
        scope: ['openid']
      }
    }
    this.registration = registration
    this.store = store
  }

  /**
   * from
   *
   * @description
   * Create a RelyingParty instance from a previously registered client.
   *
   * @param {object} data
   * @returns {Promise<RelyingParty>}
   */
  static async from (data) {
    const rp = new RelyingParty(data)
    const validation = rp.validate()

    // schema validation
    if (!validation.valid) {
      throw validation.error
    }

    const jwks = rp.provider.jwks

    // request the JWK Set if missing
    if (!jwks) {
      await rp.jwks()
      return rp
    }

    // otherwise import the JWK Set to webcrypto
    rp.provider.jwks = await JWKSet.importKeys(jwks)
    return rp
  }

  /**
   * register
   *
   * @param issuer {string} Provider URL
   * @param registration {object} Client dynamic registration options
   * @param options {object}
   * @param options.defaults
   * @param [options.store] {Session|Storage}
   * @param [oobRegistration] {object} Object providing getRegistration(key) function for out-of-band registrations
   * @param [idpId] {string} A tag identifying the provider used for looking up out-of-band registration data.
   * @returns {Promise<RelyingParty>} RelyingParty instance, registered.
   */
  static async register (issuer, registration, options, idpId, oobRegistration) {
    const rp = new RelyingParty({
      provider: { url: issuer },
      defaults: Object.assign({}, options.defaults),
      store: options.store
    })

    await rp.discover()
    await rp.jwks()
    assert(rp.provider.configuration,
      'OpenID Configuration is not initialized.')

    if (rp.provider.configuration.registration_endpoint) {
      await rp.register(registration)
    } else {
      await rp.getRegistration(registration, idpId, oobRegistration)
    }

    return rp
  }

  validate () {
    if (!this.provider || !this.provider.url) {
      return {
        valid: false,
        error: new Error('Provider url is required.')
      }
    }

    return { valid: true }
  }

  /**
   * Discover
   *
   * @description Fetches the issuer's OpenID Configuration.
   * @returns {Promise<Object>} Resolves with the provider configuration response
   */
  async discover () {
    const issuer = this.provider.url

    assert(issuer, 'RelyingParty provider must define "url"')

    const url = new URL('.well-known/openid-configuration', issuer)

    const discoverUrl = url.toString()

    let response
    try {
      response = await fetch(discoverUrl)
        .then(onHttpError('Error fetching openid configuration'))
    } catch (e) {
      const error = new Error(
        `Error fetching issuer openid-configuration "${discoverUrl}": ` +
        e.message
      )
      error.cause = e
      error.statusCode = 400
      throw error
    }

    const json = await response.json()
    this.provider.configuration = json
    return json
  }

  /**
   * Register
   *
   * @description Register's a client with provider as a Relying Party
   *
   * @param options {object}
   * @returns {Promise<Object>} Resolves with the registration response object
   */
  async register (options) {
    const { configuration } = this.provider

    assert(configuration, 'OpenID Configuration is not initialized.')
    assert(configuration.registration_endpoint,
      'OpenID Configuration is missing registration_endpoint.')

    const uri = configuration.registration_endpoint
    const method = 'post'
    const headers = new Headers({ 'Content-Type': 'application/json' })
    const params = this.defaults.register
    const body = JSON.stringify(Object.assign({}, params, options))

    const response = await fetch(uri, { method, headers, body })
      .then(onHttpError('Error registering client'))
    const json = await response.json()
    this.registration = json
    return json
  }

  serialize () {
    return JSON.stringify(this)
  }

  /**
   * @description
   * Retrieves an existing Relying Party registration for a provider which does
   * not support dynamic registration and which requires pre-registration by
   * some 'out of band' method.
   *
   * @param options {object}
   * @param idp {string} Key identifying which registration data should be retrieved.
   * @returns {Promise<Object>} Resolves with the registration response object.
   */
  async getRegistration (options, idp, oobRegistration) {
    this.registration = await oobRegistration.getRegistration(idp)
    return this.registration
  }

  /**
   * jwks
   *
   * @description Promises the issuer's JWK Set.
   * @returns {Promise}
   */
  async jwks () {
    const { configuration } = this.provider

    assert(configuration, 'OpenID Configuration is not initialized.')
    assert(configuration.jwks_uri,
      'OpenID Configuration is missing jwks_uri.')

    const uri = configuration.jwks_uri

    const response = await fetch(uri)
      .then(onHttpError('Error resolving provider keys'))
    const json = await response.json()
    const jwks = await JWKSet.importKeys(json)
    this.provider.jwks = jwks
    return jwks
  }

  /**
   * createRequest
   *
   * @param options {object} Authn request options hashmap
   * @param options.redirect_uri {string}
   * @param options.response_type {string} e.g. 'code' or 'id_token token'
   * @param session {Session|Storage} req.session or localStorage
   * @returns {Promise<string>} Authn request URL
   */
  async createRequest (options, session) {
    return AuthenticationRequest.create(this, options, session || this.store)
  }

  /**
   * Validate Response
   *
   * @param response {string} req.query or req.body.text
   * @param session {Session|Storage} req.session or localStorage or similar
   *
   * @returns {Promise<Session>}
   */
  async validateResponse (response, session = this.store) {
    let redirect, body

    if (response.match(/^http(s?):\/\//)) {
      redirect = response
    } else {
      body = response
    }

    const { params, mode } = AuthenticationResponse.parseResponse({ redirect, body })

    const options = { rp: this, session, params, mode }

    const authResponse = new AuthenticationResponse(options)

    return AuthenticationResponse.validateResponse(authResponse)
  }

  /**
   * userinfo
   *
   * @description
   * Promises the authenticated user's claims.
   * access_token can be supplied directly. If not, it is retrieved from storage, if available.
   * Depending on when userinfo is called, access_token may not yet have been saved to storage.
   *
   * @param accessToken {string=} Optional access token from current user session for use against the User Info endpoint
   * @returns {Promise}
   */
  async userinfo (accessToken) {
    const { configuration } = this.provider

    assert(configuration, 'OpenID Configuration is not initialized.')
    assert(configuration.userinfo_endpoint, 'OpenID Configuration is missing userinfo_endpoint.')

    accessToken = accessToken || this.store.access_token
    assert(accessToken, 'Missing access token.')

    const uri = configuration.userinfo_endpoint
    const headers = new Headers({
      'Content-Type': 'application/json',
      Authorization: `Bearer ${accessToken}`
    })

    return fetch(uri, { headers })
      .then(onHttpError('Error fetching userinfo'))
      .then(response => response.json())
  }

  /**
   * logoutRequest
   *
   * Composes and returns the logout request URI, based on the OP's
   * `end_session_endpoint`, with appropriate parameters.
   *
   * Note: Calling client code has the responsibility to clear the local
   * session state (for example, by calling `rp.clearSession()`). In addition,
   * some IdPs (such as Google) may not provide an `end_session_endpoint`,
   * in which case, this method will return null.
   *
   * @see https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
   *
   * @throws {Error} If provider config is not initialized
   *
   * @throws {Error} If `post_logout_redirect_uri` was provided without a
   *   corresponding `id_token_hint`
   *
   * @param [options={}] {object}
   *
   * @param [options.id_token_hint] {string} RECOMMENDED.
   *   Previously issued ID Token passed to the logout endpoint as
   *   a hint about the End-User's current authenticated session with the
   *   Client. This is used as an indication of the identity of the End-User
   *   that the RP is requesting be logged out by the OP. The OP *need not* be
   *   listed as an audience of the ID Token when it is used as an
   *   `id_token_hint` value.
   *
   * @param [options.post_logout_redirect_uri] {string} OPTIONAL. URL to which
   *   the RP is requesting that the End-User's User Agent be redirected after
   *   a logout has been performed. The value MUST have been previously
   *   registered with the OP, either using the `post_logout_redirect_uris`
   *   Registration parameter or via another mechanism. If supplied, the OP
   *   SHOULD honor this request following the logout.
   *
   *   Note: The requirement to validate the uri for previous registration means
   *   that, in practice, the `id_token_hint` is REQUIRED if
   *   `post_logout_redirect_uri` is used. Otherwise, the OP has no way to get
   *   the `client_id` to load the saved client registration, to validate the
   *   uri. The only way it can get it is by decoding the `id_token_hint`.
   *
   * @param [options.state] {string} OPTIONAL. Opaque value used by the RP to
   *   maintain state between the logout request and the callback to the
   *   endpoint specified by the `post_logout_redirect_uri` query parameter. If
   *   included in the logout request, the OP passes this value back to the RP
   *   using the `state` query parameter when redirecting the User Agent back to
   *   the RP.
   *
   * TODO: In the future, consider adding `response_mode` param, for the OP to
   *   determine how to return the `state` back the RP.
   *   @see http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes
   *
   * TODO: Handle special cases for popular providers (Google, MSFT)
   *
   * @returns {string|null} Logout uri (or null if no end_session_endpoint was
   *   provided in the IdP config)
   */
  logoutRequest (options = {}) {
    const { id_token_hint, post_logout_redirect_uri, state } = options

    assert(this.provider, 'OpenID Configuration is not initialized')

    const { configuration } = this.provider
    assert(configuration, 'OpenID Configuration is not initialized')

    if (!configuration.end_session_endpoint) {
      console.log('OpenId Configuration for ' +
        `${configuration.issuer} is missing end_session_endpoint`)
      return null
    }

    if (post_logout_redirect_uri && !id_token_hint) {
      throw new Error('id_token_hint is required when using post_logout_redirect_uri')
    }

    const params = {}

    if (id_token_hint) {
      params.id_token_hint = id_token_hint
    }
    if (post_logout_redirect_uri) {
      params.post_logout_redirect_uri = post_logout_redirect_uri
    }
    if (state) {
      params.state = state
    }

    const url = new URL(configuration.end_session_endpoint)
    url.search = FormUrlEncoded.encode(params)

    return url.href
  }

  /**
   * Logout
   *
   * @deprecated
   *
   * TODO: Add deprecation warnings, then remove. Client code should
   *   use `logoutRequest()` instead
   *
   * @returns {Promise}
   */
  logout () {
    let configuration
    try {
      assert(this.provider, 'OpenID Configuration is not initialized.')
      configuration = this.provider.configuration
      assert(configuration, 'OpenID Configuration is not initialized.')
    } catch (error) {
      return Promise.reject(error)
    }

    if (!configuration.end_session_endpoint) {
      this.clearSession()
      return Promise.resolve(undefined)
    }

    const uri = configuration.end_session_endpoint
    const method = 'get'

    return fetch(uri, { method, credentials: 'include' })
      .then(onHttpError('Error logging out'))
      .then(() => this.clearSession())

    // TODO: Validate `frontchannel_logout_uri` if necessary
    /**
     * frontchannel_logout_uri - OPTIONAL. RP URL that will cause the RP to log
     * itself out when rendered in an iframe by the OP.
     *
     * An `iss` (issuer) query parameter and a `sid`
     * (session ID) query parameter MAY be included by the OP to enable the RP
     * to validate the request and to determine which of the potentially
     * multiple sessions is to be logged out. If a sid (session ID) query
     * parameter is included, an iss (issuer) query parameter MUST also be
     * included.
     * @see https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPLogout
     */
  }

  clearSession () {
    const session = this.store

    if (!session) { return }

    delete session[SESSION_PRIVATE_KEY]
  }
}

const SESSION_PRIVATE_KEY = 'oidc.session.privateKey'

RelyingParty.SESSION_PRIVATE_KEY = SESSION_PRIVATE_KEY

module.exports = RelyingParty
