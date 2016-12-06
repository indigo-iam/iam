package it.infn.mw.iam.authn;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

public class ExternalAuthenticationFailureHandler extends ExternalAuthenticationHandlerSupport
    implements AuthenticationFailureHandler {

  private static final Logger LOG =
      LoggerFactory.getLogger(ExternalAuthenticationFailureHandler.class);

  private final AuthenticationExceptionMessageHelper helper;

  public ExternalAuthenticationFailureHandler(AuthenticationExceptionMessageHelper errorHelper) {
    this.helper = errorHelper;
  }

  private String buildRedirectURL(AuthenticationException exception) {
    String errorMessage = helper.buildErrorMessage(exception);

    try {
      errorMessage = UriUtils.encode(errorMessage, StandardCharsets.UTF_8.toString());
    } catch (UnsupportedEncodingException uex) {
      // Unlikely
    }

    return UriComponentsBuilder.fromPath("/login")
      .queryParam("error", "true")
      .queryParam("externalAuthenticationError", errorMessage)
      .build(true)
      .toString();
  }

  @Override
  public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException exception) throws IOException, ServletException {

    String errorMessage = exception.getMessage();

    if (exception.getCause() != null) {
      errorMessage = exception.getCause().getMessage();
    }

    LOG.info("External authentication failure: {}", errorMessage, exception);

    saveAuthenticationErrorInSession(request, exception);

    if (hasOngoingAccountLinking(request)) {

      restoreSavedAuthentication(request.getSession());

      clearAccountLinkingSessionAttributes(request.getSession());

      response.sendRedirect("/dashboard");
      return;
    }

    response.sendRedirect(buildRedirectURL(exception));

  }

}
