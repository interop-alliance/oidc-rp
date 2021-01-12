'use strict'

/**
 * Test dependencies
 */
const chai = require('chai')

/**
 * Assertions
 */
chai.should()

/**
 * Code under test
 */
const FormUrlEncoded = require('../src/FormUrlEncoded')

/**
 * Tests
 */
describe('FormUrlEncoded', () => {
  describe('encode', () => {
    it('should return a string', () => {
      (typeof FormUrlEncoded.encode({
        w: 'whisky',
        t: 'tango',
        f: 'foxtrot'
      })).should.equal('string')
    })

    it('should separate key and value with "="', () => {
      const encoded = FormUrlEncoded.encode({
        w: 'whisky',
        t: 'tango',
        f: 'foxtrot'
      })

      encoded.should.contain('w=whisky')
      encoded.should.contain('t=tango')
      encoded.should.contain('f=foxtrot')
    })

    it('should separate key/value pairs with "&"', () => {
      const encoded = FormUrlEncoded.encode({
        w: 'whisky',
        t: 'tango',
        f: 'foxtrot'
      })

      encoded.split('&').should.eql([
        'w=whisky',
        't=tango',
        'f=foxtrot'
      ])
    })

    it('should URI encode keys and values', () => {
      FormUrlEncoded.encode({
        'https://anvil.io': 'hammering bits into shape'
      }).should.equal('https%3A%2F%2Fanvil.io=hammering%20bits%20into%20shape')
    })
  })

  describe('decode', () => {
    it('should return an object', () => {
      (typeof FormUrlEncoded.decode('a=1')).should.equal('object')
    })

    it('should parse key/value pairs', () => {
      const decoded = FormUrlEncoded.decode('alpha=bet&beta=max')
      decoded.alpha.should.equal('bet')
      decoded.beta.should.equal('max')
    })

    it('should decode URI components', () => {
      const data = 'https%3A%2F%2Fanvil.io=hammering%20bits%20into%20shape'
      const decoded = FormUrlEncoded.decode(data)
      decoded['https://anvil.io'].should.equal('hammering bits into shape')
    })
  })
})
