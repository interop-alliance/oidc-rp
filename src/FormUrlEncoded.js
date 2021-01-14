/**
 * Dependencies
 */

/**
 * FormUrlEncoded
 */
class FormUrlEncoded {
  /**
   * Encode
   *
   * @description
   * Represent an object as x-www-form-urlencoded string.
   *
   * @param {object} data
   * @returns {string}
   */
  static encode (data) {
    const pairs = []

    Object.keys(data).forEach(function (key) {
      pairs.push(encodeURIComponent(key) + '=' + encodeURIComponent(data[key]))
    })

    return pairs.join('&')
  }

  /**
   * Decode
   *
   * @description
   * Parse a x-www-form-urlencoded into an object.
   *
   * @param {string} data
   * @returns {object}
   */
  static decode (data) {
    const obj = {}

    data.split('&').forEach(function (property) {
      const pair = property.split('=')
      const key = decodeURIComponent(pair[0])
      const val = decodeURIComponent(pair[1])

      obj[key] = val
    })

    return obj
  }
}

/**
 * Export
 */
module.exports = FormUrlEncoded
