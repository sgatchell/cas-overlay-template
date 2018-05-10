package org.plos.cas.authenticationHandler;

import javax.security.auth.login.LoginException;

public class PasswordIncorrectException extends LoginException {
  public PasswordIncorrectException() {
    super();
  }
  public PasswordIncorrectException(String msg) {
    super(msg);
  }
}

