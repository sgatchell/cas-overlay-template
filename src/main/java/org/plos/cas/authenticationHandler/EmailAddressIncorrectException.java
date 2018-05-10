package org.plos.cas.authenticationHandler;

import javax.security.auth.login.LoginException;

public class EmailAddressIncorrectException extends LoginException {
  public EmailAddressIncorrectException() {
    super();
  }
  public EmailAddressIncorrectException(String msg) {
    super(msg);
  }
}
