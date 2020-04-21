/*
* @adonisjs/auth
*
* (c) Harminder Virk <virk@adonisjs.com>
*
* For the full copyright and license information, please view the LICENSE
* file that was distributed with this source code.
*/

import { EmitterContract } from '@ioc:Adonis/Core/Event'
import { randomString, Exception } from '@poppinss/utils'
import { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'

import {
  ProviderContract,
  SessionGuardConfig,
  ProviderUserContract,
  SessionLoginEventData,
  SessionGuardContract,
  SessionAuthenticateEventData,
} from '@ioc:Adonis/Addons/Auth'

import { AuthenticationFailureException } from '../../Exceptions/AuthenticationFailureException'
import { CredentialsVerficationException } from '../../Exceptions/CredentialsVerficationException'

/**
 * Session guard enables user login using sessions. Also it allows for
 * setting remember me tokens for life long login
 */
export class SessionGuard implements SessionGuardContract<any, any> {
  constructor (
    public name: string,
    private config: SessionGuardConfig<any>,
    private emitter: EmitterContract,
    public provider: ProviderContract<any>,
    private ctx: HttpContextContract,
  ) {
  }

  /**
   * Number of years for the remember me token expiry
   */
  private rememberMeTokenExpiry = '5y'

  /**
   * Whether or not the authentication has been attempted
   * for the current request
   */
  public authenticationAttempted = false

  /**
   * Find if the user has been logged out in the current request
   */
  public isLoggedOut = false

  /**
   * A boolean to know if user is retrieved by authenticating
   * the current request or not
   */
  public isAuthenticated = false

  /**
   * A boolean to know if user is loggedin via remember me token
   * or not.
   */
  public viaRemember = false

  /**
   * Logged in or authenticated user
   */
  public user?: any

  /**
   * The name of the session key name
   */
  public get sessionKeyName () {
    return `auth_${this.name}`
  }

  /**
   * The name of the session key name
   */
  public get rememberMeKeyName () {
    return `remember_${this.name}`
  }

  /**
   * Accessor to know if user is logged in
   */
  public get isLoggedIn () {
    return !!this.user
  }

  /**
   * Accessor to know if user is a guest. It is always opposite
   * of [[isLoggedIn]]
   */
  public get isGuest () {
    return !this.isLoggedIn
  }

  /**
   * Set the user id inside the session. Also forces the session module
   * to re-generate the session id
   */
  private setSession (userId: string | number) {
    this.ctx.session.put(this.sessionKeyName, userId)
    this.ctx.session.regenerate()
  }

  /**
   * Generate remember me token
   */
  private generateRememberMeToken (): string {
    return randomString(20)
  }

  /**
   * Sets the remember me cookie with the remember me token
   */
  private setRememberMeCookie (userId: string | number, token: string) {
    const value = {
      id: userId,
      token: token,
    }

    this.ctx.response.encryptedCookie(this.rememberMeKeyName, value, {
      maxAge: this.rememberMeTokenExpiry,
      httpOnly: true,
    })
  }

  /**
   * Clears the remember me cookie
   */
  private clearRememberMeCookie () {
    this.ctx.response.clearCookie(this.rememberMeKeyName)
  }

  /**
   * Marks the user as logged out
   */
  private markUserAsLoggedOut () {
    this.isLoggedOut = true
    this.isAuthenticated = false
    this.viaRemember = false
    this.user = null
  }

  /**
   * Marks user as logged-in
   */
  private markUserAsLoggedIn (user: any, authenticated?: boolean, viaRemember?: boolean) {
    this.user = user
    this.isLoggedOut = false
    authenticated && (this.isAuthenticated = true)
    viaRemember && (this.viaRemember = true)
  }

  /**
   * Clears user session and remember me cookie
   */
  private clearUserFromStorage () {
    this.ctx.session.forget(this.sessionKeyName)
    this.clearRememberMeCookie()
  }

  /**
   * Returns data packet for the login event. Arguments are
   *
   * - The mapping identifier
   * - Logged in user
   * - HTTP context
   * - Remember me token (optional)
   */
  private getLoginEventData (user: any, token: string | null): SessionLoginEventData<any> {
    return {
      name: this.name,
      ctx: this.ctx,
      user,
      token,
    }
  }

  /**
   * Returns data packet for the authenticate event. Arguments are
   *
   * - The mapping identifier
   * - Logged in user
   * - HTTP context
   * - A boolean to tell if logged in viaRemember or not
   */
  private getAuthenticateEventData (user: any, viaRemember: boolean): SessionAuthenticateEventData<any> {
    return {
      name: this.name,
      ctx: this.ctx,
      user,
      viaRemember,
    }
  }

  /**
   * Lookup user using UID
   */
  private async lookupUsingUid (uid: string): Promise<ProviderUserContract<any>> {
    const providerUser = await this.provider.findByUid(uid)
    if (!providerUser.user) {
      throw CredentialsVerficationException.invalidUid(this.config.provider.uids)
    }

    return providerUser
  }

  /**
   * Verify user password
   */
  private async verifyPassword (providerUser: ProviderUserContract<any>, password: string): Promise<void> {
    /**
     * Verify password or raise exception
     */
    const verified = await providerUser.verifyPassword(password)
    if (!verified) {
      throw CredentialsVerficationException.invalidPassword()
    }
  }

  /**
   * Returns the user id for the current HTTP request
   */
  private getRequestSessionId () {
    return this.ctx.session.get(this.sessionKeyName)
  }

  /**
   * Verifies the remember me token
   */
  private verifyRememberMeToken (rememberMeToken: any): asserts rememberMeToken is { id: string, token: string } {
    if (!rememberMeToken || !rememberMeToken.id || !rememberMeToken.token) {
      throw AuthenticationFailureException.missingSession()
    }
  }

  /**
   * Returns user from the user session id
   */
  private async getUserForSessionId (id: string | number) {
    const authenticatable = await this.provider.findById(id)
    if (!authenticatable.user) {
      throw AuthenticationFailureException.missingUser()
    }

    return authenticatable
  }

  /**
   * Returns user for the remember me token
   */
  private async getUserForRememberMeToken (id: string, token: string) {
    const authenticatable = await this.provider.findByToken(id, token)
    if (!authenticatable.user) {
      throw AuthenticationFailureException.missingUser()
    }

    return authenticatable
  }

  /**
   * Returns the remember me token of the user that is persisted
   * inside the db. If not persisted, we create one and persist
   * it
   */
  private async getPersistedRememberMeToken (providerUser: ProviderUserContract<any>): Promise<string> {
    /**
     * Create and persist the user remember me token, when an existing one is missing
     */
    if (!providerUser.getRememberMeToken()) {
      this.ctx.logger.trace('generating fresh remember me token')
      providerUser.setRememberMeToken(this.generateRememberMeToken())
      await this.provider.updateRememberMeToken(providerUser)
    }

    return providerUser.getRememberMeToken()!
  }

  /**
   * Verifies user credentials
   */
  public async verifyCredentials (uid: string, password: string): Promise<any> {
    const providerUser = await this.lookupUsingUid(uid)
    await this.verifyPassword(providerUser, password)
    return providerUser.user
  }

  /**
   * Verify user credentials and perform login
   */
  public async attempt (uid: string, password: string, remember?: boolean): Promise<any> {
    const providerUser = await this.lookupUsingUid(uid)
    await this.verifyPassword(providerUser, password)
    await this.login(providerUser.user, remember)
    return providerUser.user
  }

  /**
   * Login user using their id
   */
  public async loginViaId (id: string | number, remember?: boolean): Promise<void> {
    const providerUser = await this.provider.findById(id)
    if (!providerUser.user) {
      throw CredentialsVerficationException.invalidId(this.config.provider.identifierKey, id)
    }

    await this.login(providerUser.user, remember)
    return providerUser.user
  }

  /**
   * Login a user
   */
  public async login (user: any, remember?: boolean): Promise<void> {
    /**
     * Since the login method is exposed to the end user, we cannot expect
     * them to instantiate and return an instance of authenticatable, so
     * we create one manually.
     */
    const providerUser = this.provider.getUserFor(user)

    /**
     * Ensure id exists on the user
     */
    const id = providerUser.getId()
    if (!id) {
      throw new Exception(`Cannot login user. Value of "${this.config.provider.identifierKey}" is not defined`)
    }

    /**
     * Set session
     */
    this.setSession(id)

    /**
     * Set remember me token when enabled
     */
    if (remember) {
      const rememberMeToken = await this.getPersistedRememberMeToken(providerUser)
      this.ctx.logger.trace('defining remember me cookie', { name: this.rememberMeKeyName })
      this.setRememberMeCookie(id, rememberMeToken)
    } else {
      /**
       * Clear remember me cookie, which may have been set previously.
       */
      this.clearRememberMeCookie()
    }

    /**
     * Emit login event. It can be used to track user logins and their devices.
     */
    this.emitter.emit(
      'auth:session:login',
      this.getLoginEventData(providerUser.user, providerUser.getRememberMeToken()),
    )

    this.markUserAsLoggedIn(providerUser.user)
    return providerUser.user
  }

  /**
   * Authenticates the current HTTP request by checking for the user
   * session.
   */
  public async authenticate (): Promise<void> {
    if (this.authenticationAttempted) {
      return
    }

    this.authenticationAttempted = true
    const sessionId = this.getRequestSessionId()

    /**
     * If session id exists, then attempt to login the user using the
     * session and return early
     */
    if (sessionId) {
      const providerUser = await this.getUserForSessionId(sessionId)
      this.markUserAsLoggedIn(providerUser.user, true)
      this.emitter.emit('auth:session:authenticate', this.getAuthenticateEventData(providerUser.user, false))
      return
    }

    /**
     * Otherwise look for remember me token. Raise exception, if both remember
     * me token and session id are missing.
     */
    const rememberMeToken = this.ctx.request.encryptedCookie(this.rememberMeKeyName)
    if (!rememberMeToken) {
      throw AuthenticationFailureException.missingSession()
    }

    /**
     * Ensure remember me token is valid after reading it from the cookie
     */
    this.verifyRememberMeToken(rememberMeToken)

    /**
     * Attempt to locate the user for remember me token
     */
    const providerUser = await this.getUserForRememberMeToken(rememberMeToken.id, rememberMeToken.token)
    this.setSession(providerUser.getId()!)
    this.setRememberMeCookie(rememberMeToken.id, rememberMeToken.token)

    this.markUserAsLoggedIn(providerUser.user, true, true)
    this.emitter.emit('auth:session:authenticate', this.getAuthenticateEventData(providerUser.user, true))
  }

  /**
   * Same as [[authenicate]] but returns a boolean over raising exceptions
   */
  public async check (): Promise<boolean> {
    try {
      await this.authenticate()
    } catch {
    }
    return this.isAuthenticated
  }

  /**
   * Logout by clearing session and cookies
   */
  public async logout (recycleRememberToken?: boolean) {
    /**
     * Return early when not attempting to re-generate the remember me token
     */
    if (!recycleRememberToken) {
      this.clearUserFromStorage()
      this.markUserAsLoggedOut()
      return
    }

    /**
     * Attempt to authenticate the current request if not already authenticated. This
     * will help us get an instance of the current user
     */
    if (!this.authenticationAttempted) {
      await this.check()
    }

    /**
     * If authentication passed, then re-generate the remember me token
     * for the current user.
     */
    if (this.user) {
      const providerUser = this.provider.getUserFor(this.user)

      this.ctx.logger.trace('re-generating remember me token')
      providerUser.setRememberMeToken(this.generateRememberMeToken())
      await this.provider.updateRememberMeToken(providerUser)
    }

    /**
     * Logout user
     */
    this.clearUserFromStorage()
    this.markUserAsLoggedOut()
  }
}