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
package org.plos.cas.authentication.handler;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Method;

import org.apereo.cas.authentication.UsernamePasswordCredential;

import org.plos.cas.authenticationHandler.DatabaseAuthenticationHandler;
import org.plos.cas.service.DatabaseService;
import org.plos.namedentity.service.PasswordDigestService;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

public class DatabaseAuthenticationHandlerTest {

  private static final String GOOD_PASSWORD = "password1";
  private static final String DB_PASSWORD   = "4f56a91f30964b93f798a0c6ae37465320119ad50f5dfd907de000621e57abf2bc76455444b8ea1e845f54db46b64e7a423f13b07f6910c9777e3d71d4715797";

  private static final String GOOD_EMAIL    = "emailindb@gmail.com";
  private static final String BAD_EMAIL     = "emailnotindb@gmail.com";
  private static final String CASID         = "af8d4adf-1629-ce51-b4a3-ea0ea28c11e0";

  private DatabaseService               databaseService;
  private DatabaseAuthenticationHandler dbauthHandler;
  private Method                        authUserMethod;
  private UsernamePasswordCredential    credentials;

  @Before
  public void setup() throws Exception {
    dbauthHandler = new DatabaseAuthenticationHandler();
    dbauthHandler.setPasswordDigestService(new PasswordDigestService());

    /* wire-up happy path mockito responses. matchers will use last match found. */
    databaseService = mock(DatabaseService.class);
    when(databaseService.getGuidFromEmailAddress(anyString())).thenReturn(CASID);
    when(databaseService.isUserVerifiedAndActive(eq(CASID))).thenReturn(true);
    when(databaseService.getPasswordFromAuthID(eq(CASID))).thenReturn(DB_PASSWORD);
    dbauthHandler.setDatabaseService(databaseService);

    authUserMethod = DatabaseAuthenticationHandler.class
                      .getDeclaredMethod("authenticateUser",UsernamePasswordCredential.class);
    authUserMethod.setAccessible(true);

    credentials = new UsernamePasswordCredential();
  }

  @Test
  public void testAuthUserUndefinedUsername() throws Exception {
    assertEquals(-3, invokeAuthUser(credentials));
  }

  @Test
  public void testAuthUserHappyPath() throws Exception {
    credentials.setUsername(GOOD_EMAIL);
    credentials.setPassword(GOOD_PASSWORD);
    assertEquals(0, invokeAuthUser(credentials));
    // verify user's email username was replaced with user's cas id.
    assertEquals(CASID, credentials.getUsername());
  }

  @Test
  public void testAuthUserBadEmailUsername() throws Exception {
    // test email -> casid username resolution. condition: email not in db ("bad")
    when(databaseService.getGuidFromEmailAddress(eq(BAD_EMAIL))).thenReturn(null);
    credentials.setUsername(BAD_EMAIL);
    assertEquals(-3, invokeAuthUser(credentials));
    // verify username wasn't altered
    assertEquals(BAD_EMAIL, credentials.getUsername());
    verify(databaseService,times(1)).getGuidFromEmailAddress(anyString());
    verify(databaseService,never()).getPasswordFromAuthID(anyString());
  }

  @Test
  public void testAuthUserNonActiveAndVerifiedUser() throws Exception {
    when(databaseService.isUserVerifiedAndActive(anyString())).thenReturn(false);
    credentials.setUsername(GOOD_EMAIL);
    assertEquals(-2, invokeAuthUser(credentials));
    verify(databaseService,times(1)).isUserVerifiedAndActive(anyString());
    verify(databaseService,never()).getPasswordFromAuthID(anyString());
  }

  @Test
  public void testAuthUserEmptyDatabasePassword() throws Exception {
    when(databaseService.getPasswordFromAuthID(anyString())).thenReturn(null);
    credentials.setUsername(GOOD_EMAIL);

    DatabaseAuthenticationHandler dbauthHandlerSpy = spy(dbauthHandler);
    assertEquals( -1, authUserMethod.invoke(dbauthHandlerSpy,credentials) );
    verify(databaseService,times(1)).getPasswordFromAuthID(anyString());
    verify(dbauthHandlerSpy,never()).verifyPassword(anyString(),anyString());
  }

  @Test
  public void testAuthUserPasswordMismatch() throws Exception {
    credentials.setUsername(GOOD_EMAIL);
    credentials.setPassword(GOOD_PASSWORD+"x");
    assertEquals(-1, invokeAuthUser(credentials));
  }

  private int invokeAuthUser(UsernamePasswordCredential userpass) throws Exception {
    return (Integer) authUserMethod.invoke(dbauthHandler,userpass);
  }
}
