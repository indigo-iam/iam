package it.infn.mw.iam.test.util.oauth;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;

public class MockOAuth2Filter extends OAuth2AuthenticationProcessingFilter {

  SecurityContext securityContext;

  public MockOAuth2Filter() {
    setAuthenticationManager(new AuthenticationManager() {

      @Override
      public Authentication authenticate(Authentication authentication)
          throws AuthenticationException {

        authentication.setAuthenticated(true);

        return authentication;
      }
    });
  }

  @Override
  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
      throws IOException, ServletException {

    if (!Objects.isNull(securityContext)) {
      SecurityContextHolder.setContext(securityContext);
    }

    chain.doFilter(req, res);
  }

  public void setSecurityContext(SecurityContext securityContext) {
    this.securityContext = securityContext;
  }

}
