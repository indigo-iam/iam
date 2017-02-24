package it.infn.mw.iam.core.util;

import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class IamAuthenticationEventPublisher implements AuthenticationEventPublisher {

  @Override
  public void publishAuthenticationSuccess(Authentication authentication) {
    IamAuthenticationLogger.INSTANCE.logAuthenticationSuccess(authentication);
  }

  @Override
  public void publishAuthenticationFailure(AuthenticationException exception,
      Authentication authentication) {


  }

}
