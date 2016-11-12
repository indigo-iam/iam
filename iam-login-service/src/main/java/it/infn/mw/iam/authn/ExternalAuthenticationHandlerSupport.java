package it.infn.mw.iam.authn;

import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;

public class ExternalAuthenticationHandlerSupport {

  public static final String ACCCOUNT_LINKING_BASE_RESOURCE = "/iam/account-linking";

  public static final String ACCOUNT_LINKING_SESSION_KEY =
      ExternalAuthenticationHandlerSupport.class.getName() + ".LINKING";

  public static final String ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION =
      ExternalAuthenticationHandlerSupport.class.getName() + ".SAVED_AUTHN";

  public static final String ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION =
      ExternalAuthenticationHandlerSupport.class.getName() + ".EXT_AUTHN";

  public static final String ACCOUNT_LINKING_ERROR_KEY =
      ExternalAuthenticationHandlerSupport.class.getName() + ".ERROR.LINKING";

  public static final String EXT_AUTHN_UNREGISTERED_USER_ROLE = "EXT_AUTH_UNREGISTERED";

  public static final GrantedAuthority EXT_AUTHN_UNREGISTERED_USER_AUTH =
      new SimpleGrantedAuthority("ROLE_" + EXT_AUTHN_UNREGISTERED_USER_ROLE);

  public static final String EXT_AUTH_ERROR_KEY =
      ExternalAuthenticationHandlerSupport.class.getName() + ".ERROR";

  protected boolean isExternalUnregisteredUser(Authentication authentication) {

    if (!(authentication instanceof AbstractExternalAuthenticationToken<?>)) {
      throw new RuntimeException("Invalid token type: " + authentication);
    }

    return authentication.getAuthorities().contains(EXT_AUTHN_UNREGISTERED_USER_AUTH);

  }

  protected boolean hasOngoingAccountLinking(HttpServletRequest request) {

    return (request.getSession().getAttribute(ACCOUNT_LINKING_SESSION_KEY) != null);
  }

  protected Authentication getAccountLinkingSavedAuthentication(HttpSession session) {
    return (Authentication) session.getAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION);
  }

  protected void saveAccountLinkingError(HttpSession session, Exception ex) {
    session.setAttribute(ACCOUNT_LINKING_ERROR_KEY, ex);
  }

  protected void clearAccountLinkingError(HttpSession session) {
    session.removeAttribute(ACCOUNT_LINKING_ERROR_KEY);
  }

  protected void clearAccountLinkingSessionAttributes(HttpSession session) {
    session.removeAttribute(ACCOUNT_LINKING_SESSION_KEY);
    session.removeAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION);
    session.removeAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION);
  }

  protected void setupAccountLinkingSessionKey(HttpSession session,
      ExternalAuthenticationType type) {
    session.setAttribute(ACCOUNT_LINKING_SESSION_KEY,
	String.format("%s/%s", ACCCOUNT_LINKING_BASE_RESOURCE, type.name()));
  }

  protected void saveAuthenticationInSession(HttpSession session, Authentication authn) {
    session.setAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION, authn);
  }

  protected void saveExternalAuthenticationInSession(HttpSession session, Authentication auth) {
    session.setAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION, auth);
  }

  protected Optional<AbstractExternalAuthenticationToken<?>> getExternalAuthenticationTokenFromSession(
      HttpSession session) {

    return Optional.ofNullable((AbstractExternalAuthenticationToken<?>) session
      .getAttribute(ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION));
  }

  protected String mapExternalAuthenticationTypeToExternalAuthnURL(
      ExternalAuthenticationType type) {
    switch (type) {
      case OIDC:
	return "/openid_connect_login";

      case SAML:
	return "/saml/login";

      default:
	throw new IllegalArgumentException("Unsupported external authentication type: " + type);
    }
  }

  protected String getAccountLinkingForwardTarget(HttpServletRequest request) {
    return String.format("%s/done", request.getSession().getAttribute(ACCOUNT_LINKING_SESSION_KEY));
  }

  protected void saveAuthenticationErrorInSession(HttpServletRequest request,
      AuthenticationException exception) {
    request.getSession().setAttribute(EXT_AUTH_ERROR_KEY, exception);
  }

  protected void restoreSavedAuthentication(HttpSession session) {
    SecurityContextHolder.getContext()
      .setAuthentication(getAccountLinkingSavedAuthentication(session));
  }



}
