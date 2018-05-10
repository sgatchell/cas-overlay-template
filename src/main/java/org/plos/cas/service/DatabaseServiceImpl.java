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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.ResultSet;
import javax.sql.DataSource;

import org.plos.namedentity.service.PasswordDigestService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Required;


/**
 * @inheritDoc
 */
public class DatabaseServiceImpl implements DatabaseService {
  private static final Logger log = LoggerFactory.getLogger(DatabaseService.class);

  private static final String queryLoginnameFromId   = "SELECT email FROM authCas WHERE LOWER(authId) = LOWER(?)";

  private static final String queryForGuidByLogin    = " SELECT authId" +
                                                       "   FROM authCas auth" +
                                                       "   JOIN emails e ON auth.emailId = e.id" +
                                                       "  WHERE LOWER(e.emailAddress) = LOWER(?)";

  private static final String queryForVerification   = " SELECT COUNT(*) " +
                                                       "   FROM authCas auth" +
                                                       "   JOIN emails e ON auth.emailId = e.id" +
                                                       "  WHERE auth.authId = ? AND e.verified = 1 AND auth.isActive = 1";

  private static final String queryForPassword       = "SELECT password FROM authCas WHERE LOWER(authId) = LOWER(?)";

  private static final String queryForToken          = " SELECT COUNT(*) " +
                                                       "   FROM authCas auth" +
                                                       "   JOIN emails e ON auth.emailId = e.id" +
                                                       "  WHERE LOWER(e.emailAddress)    = LOWER(?) " +
                                                       "    AND LOWER(verificationToken) = LOWER(?)";

  private static final String queryForEmailId        = " SELECT e.id" +
                                                       "   FROM emails e" +
                                                       "   JOIN globalTypes gt ON e.sourceTypeId = gt.id" +
                                                       "        AND gt.shortDescription = 'Ambra'" +
                                                       "   JOIN typeDescriptions td ON gt.typeId = td.id" +
                                                       "        AND td.description = 'Source Applications'" +
                                                       "  WHERE LOWER(emailAddress) = LOWER(?)";

  private static final String queryForRemoveToken    = " UPDATE authCas " +
                                                       "    SET verificationToken = null, lastModified = NOW()" +
                                                       "  WHERE emailId = ? AND LOWER(verificationToken) = LOWER(?)";

  private static final String queryForPasswordReset  = "SELECT COUNT(*) FROM authCas WHERE authId = ? AND passwordReset = 1";

  private static final String queryForPasswordUpdate = " UPDATE authCas" +
                                                       "    SET password = ?, passwordReset = 0, lastModified = NOW()" +
                                                       "  WHERE authId   = ?";

  private DataSource dataSource;
  private PasswordDigestService passwordDigestService;

  /**
   * @inheritDoc
   */
  public String getEmailAddressFromGuid (final String guid) throws SQLException {
    String emailAddress = null;

    Connection connection = null;
    PreparedStatement preparedStatement = null;
    ResultSet resultSet = null;

    try {
      connection = dataSource.getConnection();
      preparedStatement = connection.prepareStatement(queryLoginnameFromId);
      preparedStatement.setString(1, guid);

      resultSet = preparedStatement.executeQuery();
      if (resultSet.next())
        emailAddress = resultSet.getString(1);
    } catch (Exception e) {
      log.error("Unable to query Email Address for GUID = " + guid, e);
    } finally {
      if (resultSet != null) {
        resultSet.close();
      }
      if (preparedStatement != null) {
        preparedStatement.close();
      }
      if (connection != null) {
        connection.close();
      }
    }

    return emailAddress;
  }

  /**
   * @inheritDoc
   */
  public int removeToken(String username, String token) throws SQLException {

    Connection        connection       = null;
    PreparedStatement emailIdQuery     = null;
    PreparedStatement removeTokenQuery = null;
    ResultSet         resultSet        = null;

    log.debug("Query to check a user's token, username: '{}', token: '{}'", username, token);

    try {
      connection = dataSource.getConnection();

      emailIdQuery = connection.prepareStatement(queryForEmailId);
      emailIdQuery.setString(1, username);
      resultSet = emailIdQuery.executeQuery();
      resultSet.next();
      int emailId = resultSet.getInt(1);

      removeTokenQuery = connection.prepareStatement(queryForRemoveToken);
      removeTokenQuery.setInt(1, emailId);
      removeTokenQuery.setString(2, token);

      return removeTokenQuery.executeUpdate();

    } catch (Exception e) {
      log.error("Unable to query for username: '{}'", username);
      log.error(e.getMessage(), e);
    } finally {
      if (emailIdQuery     != null) { emailIdQuery.close();     }
      if (resultSet        != null) { resultSet.close();        }
      if (removeTokenQuery != null) { removeTokenQuery.close(); }
      if (connection       != null) { connection.close();       }
    }

    return 0;
  }

  /**
   * @inheritDoc
   */

  public boolean isPasswordFlagSet(String authID) throws SQLException
  {
    Connection connection = null;
    PreparedStatement preparedStatement = null;

    log.debug("Query to set a user's password, authID: '{}'", authID);

    try {
      connection = dataSource.getConnection();
      preparedStatement = connection.prepareStatement(queryForPasswordReset);
      preparedStatement.setString(1, authID);
      ResultSet resultSet = preparedStatement.executeQuery();
      resultSet.next();

      return resultSet.getInt(1) > 0;
    } finally {
      if (preparedStatement != null) {
        preparedStatement.close();
      }
      if (connection != null) {
        connection.close();
      }
    }
  }

  /**
   * @inheritDoc
   */
  public void resetUserPassword(final String authID, final String password) throws SQLException {
    Connection connection = null;
    PreparedStatement preparedStatement = null;

    log.debug("Query to set a user's password, authID: '{}'", authID);

    try {
      connection = dataSource.getConnection();
      preparedStatement = connection.prepareStatement(queryForPasswordUpdate);
      preparedStatement.setString(1, passwordDigestService.generateDigest(password));
      preparedStatement.setString(2, authID);
      preparedStatement.executeUpdate();

    } finally {
      if (preparedStatement != null) {
        preparedStatement.close();
      }
      if (connection != null) {
        connection.close();
      }
    }
  }

  /**
   * @inheritDoc
   */
  public boolean verifyToken(final String username, final String token) throws SQLException {
    Connection connection = null;
    PreparedStatement preparedStatement = null;
    ResultSet resultSet = null;

    log.debug("Query to check a user's token, username: '{}', token: '{}'", username, token);

    try {
      connection = dataSource.getConnection();
      preparedStatement = connection.prepareStatement(queryForToken);
      preparedStatement.setString(1, username);
      preparedStatement.setString(2, token);
      resultSet = preparedStatement.executeQuery();

      int count = 0;
      if (resultSet.next()) {
        count = resultSet.getInt(1);
      }
      return count > 0;
    } catch (Exception e) {
      log.error("Unable to query for username: '{}'", username);
      log.error(e.getMessage(), e);
    } finally {
      if (resultSet != null) {
        resultSet.close();
      }
      if (preparedStatement != null) {
        preparedStatement.close();
      }
      if (connection != null) {
        connection.close();
      }
    }

    return false;
  }

  /**
   * @inheritDoc
   */
  public String getGuidFromEmailAddress (final String email) throws SQLException {
    String guid = null;
    Connection connection = null;
    PreparedStatement preparedStatement = null;
    ResultSet resultSet = null;

    try {
      connection = dataSource.getConnection();
      preparedStatement = connection.prepareStatement(queryForGuidByLogin);
      preparedStatement.setString(1, email);

      resultSet = preparedStatement.executeQuery();
      if (resultSet.next()) {
        guid = resultSet.getString(1);
      }
    }
    catch (Exception e) {
      log.error("Unable to query Guid for email address = " + email, e);
    }
    finally {
      if (resultSet != null) {
        resultSet.close();
      }
      if (preparedStatement != null) {
        preparedStatement.close();
      }
      if (connection != null) {
        connection.close();
      }
    }

    return guid;
  }

  /**
   * @inheritDoc
   */
  public boolean isUserVerifiedAndActive(final String username) throws SQLException {
    Connection connection = null;
    PreparedStatement preparedStatement = null;
    ResultSet resultSet = null;

    log.debug("Query to check if a user is both verified and active: {}", username);

    try {
      connection = dataSource.getConnection();
      preparedStatement = connection.prepareStatement(queryForVerification);
      preparedStatement.setString(1, username);
      resultSet = preparedStatement.executeQuery();

      int count = 0;
      if (resultSet.next()) {
        count = resultSet.getInt(1);
      }
      return count > 0;
    }
    catch (Exception e) {
      log.error("Unable to query for email address = " + username, e);
    }
    finally {
      if (resultSet != null) {
        resultSet.close();
      }
      if (preparedStatement != null) {
        preparedStatement.close();
      }
      if (connection != null) {
        connection.close();
      }
    }

    return false;
  }

  /**
   * @inheritDoc
   */
  public String getPasswordFromAuthID(final String authID) throws SQLException {
    String password = null;

    Connection connection = null;
    PreparedStatement preparedStatement = null;
    ResultSet resultSet = null;

    try {
      connection = dataSource.getConnection();
      preparedStatement = connection.prepareStatement(queryForPassword);
      preparedStatement.setString(1, authID);
      resultSet = preparedStatement.executeQuery();
      if (resultSet.next()) {
        password = resultSet.getString(1);
      }
    }
    catch (Exception e) {
      log.error("Unable to query Password for authID = " + authID, e);
    }
    finally {
      if (resultSet != null) {
        resultSet.close();
      }
      if (preparedStatement != null) {
        preparedStatement.close();
      }
      if (connection != null) {
        connection.close();
      }
    }

    return password;
  }


  @Required
  public void setDataSource(DataSource dataSource) {
    this.dataSource = dataSource;
  }

  @Required
  public void setPasswordDigestService(PasswordDigestService passwordDigestService) {
    this.passwordDigestService = passwordDigestService;
  }
}
