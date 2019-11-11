# OpenID Connect Relying Party _(oidc-rp)_

[![Build Status](https://travis-ci.org/interop/oidc-rp.svg?branch=master&style=flat-square)](https://travis-ci.org/interop/oidc-rp)
[![npm version](https://badge.fury.io/js/%40interop%2Foidc-rp.svg)](https://badge.fury.io/js/%40interop%2Foidc-rp)

> OpenID Connect Relying Party for Node.js and the browser.

- [x] Dynamic Configuration and Client Registration
- [x] Authorization Code, Implicit, and Hybrid grants
- [x] Relying Party initiated logout
- [ ] Refresh grant
- [ ] Client Credentials grant
- [ ] Key rotation using JWK `kid` value
- [ ] Session management
- [ ] front- and back-channel logout
- [X] Request parameters as JWT
- [ ] Claims request parameter
- [ ] Claims language tags
- [ ] OAuth 2.0 Bearer Token requests

## Table of Contents

* [Security](#security)
* [Background](#background)
* [Install](#install)
* [Usage](#usage)
  * [Node.js](#nodejs)
  * [Browser](#browser)
* [Develop](#develop)
* [Maintainers](#maintainers)
* [Contribute](#contribute)
* [MIT License](#mit-license)

## Security

...

## Background

...

## Install

```bash
$ npm install @solid/oidc-rp --save
```

## Usage

### Node.js

```
const RelyingParty = require('@solid/oidc-rp')
```

### Browser

When loaded into an HTML page via `<script src="./dist/oidc.rp.min.js"></script>`,
the library is exposed as a global var, `OIDC`.


## Develop

### Install

```bash
$ git clone git@github.com:solid/oidc-rp.git
$ cd oidc-rp
$ npm install
```

### Build

**Important:**
If you're using this library as a dependency and you plan to use Webpack, don't
forget to add the following lines to your `webpack.config.js` `externals:` 
section:

```js
  externals: {
    'node-fetch': 'fetch',
    '@sinonjs/text-encoding': 'TextEncoder',
    'whatwg-url': 'window',
    'isomorphic-webcrypto': 'crypto'
  }
```

To build a Webpack-generated bundle:

```bash
npm run dist
```

### Test

```bash
npm test
```

## Maintainers

* Dmitri Zagidulin

## Contribute

#### Style guide

* ES6
* Standard JavaScript
* jsdocs

### Code of conduct

* @solid/oidc-rp follows the [Contributor Covenant](http://contributor-covenant.org/version/1/3/0/) Code of Conduct.

### Contributors

* Christian Smith [@christiansmith](https://github.com/christiansmith)
* Dmitri Zagidulin [@dmitrizagidulin](https://github.com/dmitrizagidulin)

## MIT License

[The MIT License](LICENSE.md)

Copyright (c) 2016 Anvil Research, Inc.
Copyright (c) 2017-2019 The Solid Project
