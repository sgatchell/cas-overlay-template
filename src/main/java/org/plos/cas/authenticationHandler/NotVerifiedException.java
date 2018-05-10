package org.plos.cas.authenticationHandler;

import javax.security.auth.login.LoginException;

public class NotVerifiedException extends LoginException {
  public NotVerifiedException() {
    super();
  }
  public NotVerifiedException(String msg) {
    super(msg);
  }
}

