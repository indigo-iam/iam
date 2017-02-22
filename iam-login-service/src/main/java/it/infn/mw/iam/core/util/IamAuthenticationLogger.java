package it.infn.mw.iam.core.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

public enum IamAuthenticationLogger implements AuthenticationLogger {

  INSTANCE;

  private final Logger LOG = LoggerFactory.getLogger(IamAuthenticationLogger.class);

  @Override
  public void logAuthenticationSuccess(Authentication auth) {
    if (!(auth instanceof OAuth2Authentication)) {
      LOG.info("{} was authenticated succesfully", auth.getName());
      return;
    }

    final OAuth2Authentication oauth = (OAuth2Authentication) auth;
    final String clientName = oauth.getName();

    if (oauth.getUserAuthentication() != null) {
      final String userName = oauth.getUserAuthentication().getName();
      LOG.info("{} acting for {} was authenticated succesfully", clientName, userName);
    } else {
      LOG.info("Client {} was authenticated succesfully", clientName);
    }
  }

}
