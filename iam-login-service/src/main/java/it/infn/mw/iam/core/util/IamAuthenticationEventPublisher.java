package it.infn.mw.iam.core.util;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class IamAuthenticationEventPublisher
    implements AuthenticationEventPublisher, ApplicationEventPublisherAware {

  private ApplicationEventPublisher eventPublisher;

  @Override
  public void publishAuthenticationSuccess(Authentication authentication) {
    IamAuthenticationLogger.INSTANCE.logAuthenticationSuccess(authentication);
    eventPublisher.publishEvent(new AuthenticationSuccessEvent(authentication));
  }

  @Override
  public void publishAuthenticationFailure(AuthenticationException exception,
      Authentication authentication) {
    eventPublisher
      .publishEvent(new AuthenticationFailureBadCredentialsEvent(authentication, exception));

  }

  @Override
  public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {

    eventPublisher = applicationEventPublisher;
  }

}
