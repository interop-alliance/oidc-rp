'use strict'

const fetch = require('cross-fetch')
const onHttpError = require('./onHttpError')
const PoPToken = require('./PoPToken')

class Session {
  /**
   * @param options {object}
   *
   * @param options.credentialType {string} 'access_token' or 'pop_token'
   *
   * @param options.issuer {string} Identity provider (issuer of ID/Access Token)
   *
   * @param options.authorization {object}
   * @param options.authorization.client_id {string} OIDC/OAuth2 client id
   * @param [options.authorization.id_token] {string} Compact-serialized id_token param
   * @param [options.authorization.access_token] {string} Compact-serialized access_token param
   * @param [options.authorization.refresh_token] {string} Compact-serialized refresh_token
   *
   * @param [options.sessionKey] {string} Serialized client session key generated
   *   during the Authentication Request, used to issue PoPTokens
   *
   * @param [options.idClaims] {object} Decoded/verified ID Token JWT payload
   *
   * @param [options.accessClaims] {object} Decoded/verified Access Token JWT payload
   */
  constructor (options) {
    this.credentialType = options.credentialType || 'access_token'

    this.issuer = options.issuer

    this.authorization = options.authorization || {}

    this.sessionKey = options.sessionKey

    this.idClaims = options.idClaims
    this.accessClaims = options.accessClaims
  }

  static from (options) {
    return new Session(options)
  }

  /**
   * @param response {AuthenticationResponse}
   *
   * @returns {Session} RelyingParty Session object
   */
  static fromAuthResponse (response) {
    const RelyingParty = require('./RelyingParty') // import here due to circular dep

    const idClaims = (response.decoded && response.decoded.payload) || {}

    const { rp } = response

    const registration = rp.registration
    const rpAuthOptions = rp.defaults.authenticate || {}

    const credentialType = rpAuthOptions.credential_type ||
      rp.defaults.popToken
      ? 'pop_token'
      : 'access_token'

    const sessionKey = response.session[RelyingParty.SESSION_PRIVATE_KEY]

    const options = {
      credentialType,
      sessionKey,
      issuer: idClaims.iss,
      idClaims,
      authorization: {
        client_id: registration.client_id,
        access_token: response.params.access_token,
        id_token: response.params.id_token,
        refresh_token: response.params.refresh_token
      }
    }

    return Session.from(options)
  }

  /**
   * Authenticated fetch() getter
   *
   * @returns {function}
   */
  get fetch () {
    /**
     * fetch() function signature
     *
     * @param url {RequestInfo|string}
     * @param options {object}
     *
     * @returns {Function<Promise<Response>>}
     */
    return async (url, options) => {
      const result = this.hasCredentials()
        ? await this.fetchWithCredentials(url, options)
        : await fetch(url, options)

      return result.then(onHttpError('Error while fetching resource'))
    }
  }

  /**
   * bearerTokenFor
   *
   * @param url {string}
   *
   * @returns {Promise<string>}
   */
  async bearerTokenFor (url) {
    switch (this.credentialType) {
      case 'pop_token':
        return PoPToken.issueFor(url, this)

      default: // 'access_token' etc
        return this.authorization[this.credentialType]
    }
  }

  /**
   * hasCredentials
   *
   * @returns {boolean}
   */
  hasCredentials () {
    switch (this.credentialType) {
      case 'pop_token':
        return !!this.authorization.id_token

      default: // 'access_token' etc
        return !!this.authorization[this.credentialType]
    }
  }

  /**
   * fetchWithCredentials
   *
   * @param url {RequestInfo|string}
   * @param options {object}
   *
   * @returns {Promise<Response>}
   */
  async fetchWithCredentials (url, options = {}) {
    options.headers = options.headers || {}

    const token = await this.bearerTokenFor(url)

    options.headers.authorization = `Bearer ${token}`

    return fetch(url, options)
  }
}

module.exports = Session
