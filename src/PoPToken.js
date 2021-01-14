'use strict'

const { JWT, JWK } = require('@solid/jose')

const DEFAULT_MAX_AGE = 3600 // Default token expiration, in seconds

class PoPToken extends JWT {
  /**
   * @param resourceServerUri {string} RS URI for which this token is intended
   *
   * @param session {Session}
   * @param session.sessionKey {string}
   * @param session.authorization.client_id {string}
   * @param session.authorization.id_token {string}
   *
   * @returns {Promise<string>} PoPToken, encoded as compact JWT
   */
  static async issueFor (resourceServerUri, session) {
    if (!resourceServerUri) {
      throw new Error('Cannot issue PoPToken - missing resource server URI')
    }

    if (!session.sessionKey) {
      throw new Error('Cannot issue PoPToken - missing session key')
    }

    if (!session.authorization.id_token) {
      throw new Error('Cannot issue PoPToken - missing id token')
    }

    const jwk = JSON.parse(session.sessionKey)
    const options = {
      aud: (new URL(resourceServerUri)).origin,
      key: (await JWK.importKey(jwk)),
      iss: session.authorization.client_id,
      id_token: session.authorization.id_token
    }
    const jwt = await PoPToken.issue(options)

    return jwt.encode()
  }

  /**
   * issue
   *
   * @param options {object}
   * @param options.iss {string} Token issuer (RP client_id)
   * @param options.aud {string|Array<string>} Audience for the token
   *   (such as the Resource Server url)
   * @param options.key {JWK} Proof of Possession (private) signing key, see
   *   https://tools.ietf.org/html/rfc7800#section-3.1
   *
   * @param options.id_token {string} JWT compact encoded ID Token
   *
   * Optional:
   * @param [options.iat] {number} Issued at timestamp (in seconds)
   * @param [options.max] {number} Max token lifetime in seconds
   *
   * @returns {PoPToken} Proof of Possession Token (JWT instance)
   */
  static issue (options) {
    const { aud, iss, key } = options

    const alg = key.alg
    const iat = options.iat || Math.floor(Date.now() / 1000)
    const max = options.max || DEFAULT_MAX_AGE

    const exp = iat + max // token expiration

    const header = { alg }
    const payload = { iss, aud, exp, iat, id_token: options.id_token, token_type: 'pop' }

    const jwt = new PoPToken({ header, payload, key: key.cryptoKey }, { filter: false })

    return jwt
  }
}

module.exports = PoPToken
