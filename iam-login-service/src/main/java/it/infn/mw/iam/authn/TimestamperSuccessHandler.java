package it.infn.mw.iam.authn;

import static org.slf4j.LoggerFactory.getLogger;

import java.io.IOException;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.mitre.openid.connect.web.AuthenticationTimeStamper;
import org.slf4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public class TimestamperSuccessHandler implements AuthenticationSuccessHandler {

  public static final Logger LOG = getLogger(TimestamperSuccessHandler.class);
  private final AuthenticationSuccessHandler delegate;

  public TimestamperSuccessHandler(AuthenticationSuccessHandler delegate) {
    this.delegate = delegate;
  }

  protected void setAuthenticationTimestamp(HttpServletRequest request,
      HttpServletResponse response, Authentication authentication) {

    Date timestamp = new Date();
    HttpSession session = request.getSession();
    session.setAttribute(AuthenticationTimeStamper.AUTH_TIMESTAMP, timestamp);
    LOG.info("{} was authenticated successfully", authentication.getName());

  }

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {

    delegate.onAuthenticationSuccess(request, response, authentication);
    setAuthenticationTimestamp(request, response, authentication);

  }

}
