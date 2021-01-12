'use strict'

/**
 * Test dependencies
 */
const chai = require('chai')

/**
 * Assertions
 */
chai.should()
chai.use(require('chai-as-promised'))
chai.use(require('dirty-chai'))
const expect = chai.expect

/**
 * Code under test
 */
const onHttpError = require('../src/onHttpError')

describe('onHttpError', () => {
  it('should pass through the response with status code < 300', () => {
    const response = { status: 200 }
    const errorHandler = onHttpError()

    expect(errorHandler(response)).to.equal(response)
  })

  it('should throw an error on http error response', () => {
    const response = { status: 400, statusText: 'Bad Request' }

    const errorHandler = onHttpError('Error during some operation')

    expect(() => errorHandler(response))
      .to.throw(/Error during some operation: 400 Bad Request/)
  })

  it('should set a default error message', () => {
    const response = { status: 404, statusText: 'Not Found' }

    const errorHandler = onHttpError()

    expect(() => errorHandler(response))
      .to.throw(/fetch error: 404 Not Found/)
  })

  it('should pass through the status code to the error', done => {
    const response = { status: 400, statusText: 'Bad Request' }

    const errorHandler = onHttpError()

    try {
      errorHandler(response)
    } catch (err) {
      expect(err.statusCode).to.equal(400)
      done()
    }
  })

  it('should set the response object on the error', done => {
    const response = { status: 500, statusText: 'Internal Server Error' }

    const errorHandler = onHttpError()

    try {
      errorHandler(response)
    } catch (err) {
      expect(err.response).to.equal(response)
      done()
    }
  })
})
