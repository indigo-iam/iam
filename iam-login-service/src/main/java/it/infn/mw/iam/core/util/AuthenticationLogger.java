package it.infn.mw.iam.core.util;

import org.springframework.security.core.Authentication;

public interface AuthenticationLogger {

  public void logAuthenticationSuccess(Authentication auth);

}
