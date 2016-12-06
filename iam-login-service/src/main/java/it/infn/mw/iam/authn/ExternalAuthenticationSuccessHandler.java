package it.infn.mw.iam.authn;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public class ExternalAuthenticationSuccessHandler extends ExternalAuthenticationHandlerSupport
    implements AuthenticationSuccessHandler {

  private final AuthenticationSuccessHandler delegate;
  private final String unregisteredUserTargetURL;

  public ExternalAuthenticationSuccessHandler(AuthenticationSuccessHandler delegate,
      String unregisteredUserTargetURL) {
    this.delegate = delegate;
    this.unregisteredUserTargetURL = unregisteredUserTargetURL;
  }

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {

    if (hasOngoingAccountLinking(request)) {

      HttpSession session = request.getSession();

      saveExternalAuthenticationInSession(session, authentication);
      restoreSavedAuthentication(session);
      setAccountLinkingDone(session);

      request.getRequestDispatcher(getAccountLinkingForwardTarget(request)).forward(request,
          response);

    } else {

      if (isExternalUnregisteredUser(authentication)) {
        response.sendRedirect(unregisteredUserTargetURL);

      } else {
        delegate.onAuthenticationSuccess(request, response, authentication);
      }

    }
  }

}
