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

package org.plos.cas.service;

import java.sql.SQLException;

public interface DatabaseService {
  /**
   * Given an ID, this method will return the username (assumed to be the email address)
   *   for that user from the database
   * 
   * @param guid The ID for a user
   * @return The <em>username</em> for the user with the ID which matches the <em>guid</em> parameter
   * @throws SQLException for any problem encountered when talking to the database
   */
  public String getEmailAddressFromGuid(String guid) throws SQLException;

  /**
   * If the given token for the given username exists, return true
   *
   * @param username the username
   * @param token the authentication token
   *
   * @return if the given token for the given username exists, returns true
   *
   * @throws SQLException
   */
  public boolean verifyToken(String username, String token) throws SQLException;

  /**
   * Remove the given token from the user's account so it can not be used again
   *
   * @param username the username
   * @param token the authentication token
   *
   * @throws SQLException
   */
  public int removeToken(String username, String token) throws SQLException;

  /**
   * Is the password flag set for the passed in user
   *
   * @param authID the authID of the the account
   *
   * @return true of the flag is set
   *
   * @throws SQLException
   */
  public boolean isPasswordFlagSet(String authID) throws SQLException;

  /**
   * Set the password for the passed in user
   *
   * @param authID the authID of the the account
   * @param password the new password value
   *
   * @throws SQLException
   */
  public void resetUserPassword(String authID, String password) throws SQLException;

  /**
   * Given an email address, return the user's GUID
   *
   * @param email the user's email address
   *
   * @return the user's GUID
   *
   * @throws SQLException
   */
  public String getGuidFromEmailAddress(String email) throws SQLException;

  /**
   * Determine if user account has been verified and is active.
   *
   * @param username Submitted by the user are part of an authentication attempt
   * @return true if email has been verified and account is active, false
   * otherwise.
   */
  public boolean isUserVerifiedAndActive(String username) throws SQLException;

  /**
   * Get the password for the given authID
   *
   * @param authID the authorizationID
   *
   * @return the password
   *
   * @throws SQLException
   */
  public String getPasswordFromAuthID(String authID) throws SQLException;
}
