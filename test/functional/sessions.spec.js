'use strict'

/*
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const { ioc } = require('@adonisjs/fold')
const test = require('japa')
const supertest = require('supertest')
const http = require('http')
const nodeReq = require('node-req')
const setup = require('./setup')
const groupSetup = require('../unit/setup')
const helpers = require('../unit/helpers')

test.group('Session', (group) => {
  groupSetup.databaseHook(group)
  groupSetup.hashHook(group)

  group.before(async () => {
    await setup()
  })

  group.beforeEach(() => {
    this.server = http.createServer()
  })

  test('throw error when credentials are invalid', async (assert) => {
    this.server.on('request', (req, res) => {
      const Context = ioc.use('Adonis/Src/HttpContext')

      const ctx = new Context()
      ctx.request = helpers.getRequest(req)
      ctx.response = helpers.getResponse(req, res)
      ctx.session = helpers.getSession(req, res)

      ctx
        .auth
        .attempt(nodeReq.get(req).email, nodeReq.get(req).password)
        .then(() => {
          res.end()
        })
        .catch(({ status, message }) => {
          res.writeHead(status)
          res.write(message)
          res.end()
        })
    })

    const { text } = await supertest(this.server).get('/?email=foo@bar.com&password=secret').expect(401)
    assert.equal(text, 'E_USER_NOT_FOUND: Cannot find user with email as foo@bar.com')
  })

  test('throw error when password is invalid', async (assert) => {
    await ioc.use('App/Models/User').create({ email: 'foo@bar.com', password: 'secret' })

    this.server.on('request', (req, res) => {
      const Context = ioc.use('Adonis/Src/HttpContext')

      const ctx = new Context()
      ctx.request = helpers.getRequest(req)
      ctx.response = helpers.getResponse(req, res)
      ctx.session = helpers.getSession(req, res)

      ctx
        .auth
        .attempt(nodeReq.get(req).email, nodeReq.get(req).password)
        .then(() => {
          res.end()
        })
        .catch(({ status, message }) => {
          res.writeHead(status)
          res.write(message)
          res.end()
        })
    })

    const { text } = await supertest(this.server).get('/?email=foo@bar.com&password=super').expect(401)
    assert.equal(text, 'E_PASSWORD_MISMATCH: Cannot verify user password')
  })

  test('set session when user credentials are correct', async (assert) => {
    await ioc.use('App/Models/User').create({ email: 'foo@bar.com', password: 'secret' })

    this.server.on('request', (req, res) => {
      const Context = ioc.use('Adonis/Src/HttpContext')

      const ctx = new Context()
      ctx.request = helpers.getRequest(req)
      ctx.response = helpers.getResponse(req, res)
      ctx.session = helpers.getSession(req, res)

      ctx
        .auth
        .attempt(nodeReq.get(req).email, nodeReq.get(req).password)
        .then(() => {
          res.writeHead(200)
          res.end()
        })
        .catch(({ status, message }) => {
          res.writeHead(status)
          res.write(message)
          res.end()
        })
    })

    const { headers } = await supertest(this.server).get('/?email=foo@bar.com&password=secret').expect(200)
    assert.equal(headers['set-cookie'][0], 'adonis-auth=1')
  })

  test('set remember token when remeber method is called', async (assert) => {
    await ioc.use('App/Models/User').create({ email: 'foo@bar.com', password: 'secret' })

    this.server.on('request', (req, res) => {
      const Context = ioc.use('Adonis/Src/HttpContext')

      const ctx = new Context()
      ctx.request = helpers.getRequest(req)
      ctx.response = helpers.getResponse(req, res)
      ctx.session = helpers.getSession(req, res)

      ctx
        .auth
        .remember(true)
        .attempt(nodeReq.get(req).email, nodeReq.get(req).password)
        .then(() => {
          res.writeHead(200)
          res.end()
        })
        .catch(({ status, message }) => {
          res.writeHead(status || 500)
          res.write(message)
          res.end()
        })
    })

    const { headers } = await supertest(this.server).get('/?email=foo@bar.com&password=secret').expect(200)
    assert.match(headers['set-cookie'][0], /adonis-remember-token=/)
    const user = await ioc.use('App/Models/User').query().with('tokens').first()
    assert.isDefined(user.getRelated('tokens').first())
    assert.equal(user.getRelated('tokens').first().token, headers['set-cookie'][0].split('=')[1])
  })

  test('get loggedin user when cookie exists', async (assert) => {
    await ioc.use('App/Models/User').create({ email: 'foo@bar.com', password: 'secret' })

    this.server.on('request', (req, res) => {
      const Context = ioc.use('Adonis/Src/HttpContext')

      const ctx = new Context()
      ctx.request = helpers.getRequest(req)
      ctx.response = helpers.getResponse(req, res)
      ctx.session = helpers.getSession(req, res)

      ctx
        .auth
        .check()
        .then((isLogged) => {
          res.writeHead(200)
          res.write(String(isLogged))
          res.end()
        })
        .catch(({ status, message }) => {
          console.log(message)
          res.writeHead(status || 500)
          res.write(message)
          res.end()
        })
    })

    const { text } = await supertest(this.server).get('/').set('Cookie', 'adonis-auth=1').expect(200)
    assert.equal(text, 'true')
  })

  test('throw exception when cookie exists but user doesn\'t', async (assert) => {
    this.server.on('request', (req, res) => {
      const Context = ioc.use('Adonis/Src/HttpContext')

      const ctx = new Context()
      ctx.request = helpers.getRequest(req)
      ctx.response = helpers.getResponse(req, res)
      ctx.session = helpers.getSession(req, res)

      ctx
        .auth
        .check()
        .then(() => {
          res.writeHead(200)
          res.end()
        })
        .catch(({ status, message }) => {
          res.writeHead(status || 500)
          res.write(message)
          res.end()
        })
    })

    const { text } = await supertest(this.server).get('/').set('Cookie', 'adonis-auth=1').expect(401)
    assert.equal(text, 'E_INVALID_SESSION: Invalid session')
  })

  test('set user property on auth when user exists', async (assert) => {
    await ioc.use('App/Models/User').create({ email: 'foo@bar.com', password: 'secret' })

    this.server.on('request', (req, res) => {
      const Context = ioc.use('Adonis/Src/HttpContext')

      const ctx = new Context()
      ctx.request = helpers.getRequest(req)
      ctx.response = helpers.getResponse(req, res)
      ctx.session = helpers.getSession(req, res)

      ctx
        .auth
        .loginIfCan()
        .then(() => {
          res.writeHead(200, { 'content-type': 'application/json' })
          res.write(JSON.stringify(ctx.auth.user))
          res.end()
        })
        .catch(({ status, message }) => {
          res.writeHead(status || 500)
          res.write(message)
          res.end()
        })
    })

    const { body } = await supertest(this.server).get('/').set('Cookie', 'adonis-auth=1').expect(200)
    assert.equal(body.id, 1)
    assert.equal(body.email, 'foo@bar.com')
    assert.equal(body.password, 'secret')
  })

  test('find user via remember_me_token', async (assert) => {
    const user = await ioc.use('App/Models/User').create({
      email: 'foo@bar.com',
      password: 'secret'
    })
    await user.tokens().create({ token: '2020', is_revoked: false, type: 'remember_token' })

    this.server.on('request', (req, res) => {
      const Context = ioc.use('Adonis/Src/HttpContext')

      const ctx = new Context()
      ctx.request = helpers.getRequest(req)
      ctx.response = helpers.getResponse(req, res)
      ctx.session = helpers.getSession(req, res)

      ctx
        .auth
        .check()
        .then((isLogged) => {
          res.writeHead(200, { 'content-type': 'application/json' })
          res.write(JSON.stringify(ctx.auth.user))
          res.end()
        })
        .catch(({ status, message }) => {
          console.log(message)
          res.writeHead(status || 500)
          res.write(message)
          res.end()
        })
    })

    const { body } = await supertest(this.server).get('/').set('Cookie', 'adonis-remember-token=2020').expect(200)
    assert.equal(body.id, 1)
    assert.equal(body.email, 'foo@bar.com')
    assert.equal(body.password, 'secret')
  })

  test('ignore silently when there is no session cookie', async (assert) => {
    await ioc.use('App/Models/User').create({ email: 'foo@bar.com', password: 'secret' })

    this.server.on('request', (req, res) => {
      const Context = ioc.use('Adonis/Src/HttpContext')

      const ctx = new Context()
      ctx.request = helpers.getRequest(req)
      ctx.response = helpers.getResponse(req, res)
      ctx.session = helpers.getSession(req, res)

      ctx
        .auth
        .loginIfCan()
        .then(() => {
          res.writeHead(200)
          res.write(ctx.auth.user || 'not logged in')
          res.end()
        })
        .catch(({ status, message }) => {
          res.writeHead(status || 500)
          res.write(message)
          res.end()
        })
    })

    const { text } = await supertest(this.server).get('/').expect(200)
    assert.equal(text, 'not logged in')
  })
})
