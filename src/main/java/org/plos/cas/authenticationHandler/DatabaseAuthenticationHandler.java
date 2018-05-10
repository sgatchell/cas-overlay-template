/*
 * Copyright (c) 2017 Public Library of Science
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
package org.plos.cas.authenticationHandler;

import java.security.GeneralSecurityException;
import javax.security.auth.login.FailedLoginException;

import org.apereo.cas.authentication.HandlerResult;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.authentication.UsernamePasswordCredential;
import org.apereo.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.apereo.cas.authentication.principal.DefaultPrincipalFactory;
import org.plos.cas.service.DatabaseService;
import org.plos.namedentity.service.PasswordDigestService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Required;

import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;

/**
 * This class authenticates users based on a submitted username/password pair.
 */
public class DatabaseAuthenticationHandler
    extends AbstractUsernamePasswordAuthenticationHandler
    implements InitializingBean {

  private static final Logger log = LoggerFactory.getLogger(DatabaseAuthenticationHandler.class);

  private static final int INCORRECT_EMAIL_ADDRESS = -3;
  private static final int EMAIL_NOT_VERIFIED = -2;
  private static final int INCORRECT_PASSWORD = -1;
  private static final int SUCCESS = 0;

  private PasswordDigestService passwordService;
  private DatabaseService databaseService;

  public DatabaseAuthenticationHandler(final String name, final ServicesManager servicesManager, final PrincipalFactory principalFactory,
                                                         final Integer order) {
    super(name, servicesManager, principalFactory, order);
  }

  public DatabaseAuthenticationHandler() {
    this("",null,null,null);
  }

  /**
   * Determine if the credentials supplied are valid.  The actual work is handled by the
   * private method <em>authenticateUser(UsernamePasswordCredentials credentials)</em>
   * <p/>
   *
   * @param credential Contains the username and password submitted by the user
   *
   * @return HandlerResult if successfully authenticates, throws exception otherwise.
   *
   * @throws GeneralSecurityException if credentials are invalid.
   * @throws PreventedException problem occurred while authenticating.
   */
  protected HandlerResult authenticateUsernamePasswordInternal(final UsernamePasswordCredential credential, final String originalPassword)
    throws GeneralSecurityException, PreventedException {

    String emailAddress = credential.getUsername();
    int authResult = authenticateUser(credential);
    if (authResult == SUCCESS) {
      // login successful. email username has been replaced with casid.
      return createHandlerResult(credential,
         new DefaultPrincipalFactory().createPrincipal(credential.getUsername()), null);
    }
    else {
      // user failed to log in. show user their email, not guid.
      if (emailAddress != null) {
        credential.setUsername(emailAddress);
      } else {
        credential.setUsername("");
      }
      if (authResult == EMAIL_NOT_VERIFIED) {
        throw new NotVerifiedException();
      } else if(authResult == INCORRECT_EMAIL_ADDRESS) {
        throw new EmailAddressIncorrectException();
      } else if(authResult == INCORRECT_PASSWORD) {
        throw new PasswordIncorrectException();
      } else {
        throw new FailedLoginException();
      }
    }
  }

  /**
   * Determine if the credentials supplied are valid.
   *
   * @param credential Contains the username and password submitted by the user
   *
   * @return 0 if the submitted password matches the stored password for this username,
   *   -1 if password is wrong or empty.
   *   -2 if email is not verified.
   *   -3 if email is wrong or empty.
   *
   * @throws PreventedException signals there was an error authenticating, such as, db
   *   exception, network failure, ...
   *
   * note 1. replace username email address with casid (aka, guid). apparently issuing a
   *         certificate with has an email address for a "name" will break Ambra's user
   *         profile page?
   */
  private final int authenticateUser(UsernamePasswordCredential credential)
    throws PreventedException {

    String username = credential.getUsername();
    try {
      if (isEmptyOrBlank(username)) {
        log.warn("Undefined username for credential. How did this happen?");
        return INCORRECT_EMAIL_ADDRESS;
      }
      // assumption: username is a valid casid or an email address. assert this?!

      // replace email address username with user's casid (see note #1)
      boolean isEmail = false;
      if (isEmailUsername(username)) {
        isEmail = true;
        String guid = databaseService.getGuidFromEmailAddress(username);
        if(isEmptyOrBlank(guid)) {
          log.info("Unable to find casid for email address = "+username);
          return INCORRECT_EMAIL_ADDRESS;
        }
        username = guid;
        credential.setUsername(username);
      }

      // is user active and email verified ?
      if ( !databaseService.isUserVerifiedAndActive(username)) {
        log.info("User {} not active or hasn't been verified", username);
        if (isEmail) {
          return EMAIL_NOT_VERIFIED;
        } else {
          return INCORRECT_EMAIL_ADDRESS;
        }
      }

      // lookup password in database
      String dbPassword = databaseService.getPasswordFromAuthID(username);
      if (isEmptyOrBlank(dbPassword)) {
        log.warn("Unable to get password in database for user {}", username);
        return INCORRECT_PASSWORD;
      }

      // verify password
      if (!verifyPassword(credential.getPassword(), dbPassword)) {
        log.info("Input password doesn't match db password for user {}", username);
        return INCORRECT_PASSWORD;
      }

    } catch (Exception e) {
      String msg = "Problem authenticating user="+username;
      log.error(msg,e);
      throw new PreventedException(msg,e);
    }
    return SUCCESS;
  }

  private boolean isEmailUsername(String username) {
    return (username.indexOf('@') > 0);
  }

  /**
   * Verify that the user password (from the database)
   * matches the digested password (submitted by the user as part of the authentication process)
   *
   * @param passwordToVerify Submitted by the user during an attempt to authenticate
   * @param passwordFromDatabase Salted and digested password previously set by the user
   * @return true if the two passwords match (after salting and encoding), false otherwise
   * @throws Exception Thrown when there are problems with the password encoder
   */
  public boolean verifyPassword(final String passwordToVerify, final String passwordFromDatabase) throws Exception {
    return this.passwordService.verifyPassword(passwordToVerify, passwordFromDatabase);
  }

  /**
   * If you want things executed or values set IMMEDIATELY AFTER the bean is created, then do so here.
   * This method is NEVER called during the user validation process.
   * <p/>
   * This (empty) method has been declared here to satisfy the requirements of the
   *   org.springframework.beans.factory.InitializingBean interface.
   */
  public void afterPropertiesSet() throws Exception {
  }

  @Required
  public void setPasswordDigestService(PasswordDigestService passwordDigestService) {
    this.passwordService = passwordDigestService;
  }

  @Required
  public void setDatabaseService(DatabaseService databaseService) {
    this.databaseService = databaseService;
  }

  private boolean isEmptyOrBlank(String s) {
    return s == null || s.trim().isEmpty();
  }
}
