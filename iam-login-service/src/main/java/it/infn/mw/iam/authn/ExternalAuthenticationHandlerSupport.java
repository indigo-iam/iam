/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.infn.mw.iam.authn;

import static it.infn.mw.iam.authn.x509.IamX509PreauthenticationProcessingFilter.X509_CREDENTIAL_SESSION_KEY;

import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang.StringEscapeUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.util.UriComponentsBuilder;

import com.google.common.base.Strings;

import it.infn.mw.iam.api.account_linking.AccountLinkingConstants;
import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.authn.error.InvalidExternalAuthenticationTokenError;
import it.infn.mw.iam.authn.x509.IamX509AuthenticationCredential;

public class ExternalAuthenticationHandlerSupport implements AccountLinkingConstants {

  public static final String ACCOUNT_LINKING_BASE_RESOURCE = "/iam/account-linking";

  public static final String ACCOUNT_LINKING_SESSION_KEY =
      ExternalAuthenticationHandlerSupport.class.getName() + ".LINKING";

  public static final String ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION =
      ExternalAuthenticationHandlerSupport.class.getName() + ".SAVED_AUTHN";

  public static final String ACCOUNT_LINKING_SESSION_EXT_AUTHENTICATION =
      ExternalAuthenticationHandlerSupport.class.getName() + ".EXT_AUTHN";

  public static final String ACCOUNT_LINKING_ERROR_KEY =
      ExternalAuthenticationHandlerSupport.class.getName() + ".ERROR.LINKING";

  public static final String ACCOUNT_LINKING_DONE_KEY =
      ExternalAuthenticationHandlerSupport.class.getName() + ".DONE";

  public static final String EXT_AUTHN_UNREGISTERED_USER_ROLE = "EXT_AUTH_UNREGISTERED";

  public static final String EXT_AUTHN_UNREGISTERED_USER_AUTH_STRING = "ROLE_" + EXT_AUTHN_UNREGISTERED_USER_ROLE;

  public static final GrantedAuthority EXT_AUTHN_UNREGISTERED_USER_AUTH =
      new SimpleGrantedAuthority(EXT_AUTHN_UNREGISTERED_USER_AUTH_STRING);

  public static final String EXT_AUTH_ERROR_KEY =
      ExternalAuthenticationHandlerSupport.class.getName() + ".ERROR";

  public static final String ACCOUNT_LINKING_DASHBOARD_MESSAGE_KEY = "accountLinkingMessage";
  public static final String ACCOUNT_LINKING_DASHBOARD_ERROR_KEY = "accountLinkingError";


  protected boolean hasAccountLinkingDoneKey(HttpSession session) {
    Object value = session.getAttribute(ACCOUNT_LINKING_DONE_KEY);
    if (value != null) {
      session.removeAttribute(ACCOUNT_LINKING_DONE_KEY);
      return true;
    }
    return false;
  }

  protected void setAccountLinkingDone(HttpSession session) {
    session.setAttribute(ACCOUNT_LINKING_DONE_KEY, "DONE");
  }

  protected boolean isExternalUnregisteredUser(Authentication authentication) {

    if (!(authentication instanceof AbstractExternalAuthenticationToken<?>)) {
      throw new InvalidExternalAuthenticationTokenError("Invalid token type: " + authentication);
    }

    return authentication.getAuthorities().contains(EXT_AUTHN_UNREGISTERED_USER_AUTH);

  }

  protected boolean hasOngoingAccountLinking(HttpServletRequest request) {

    return (request.getSession().getAttribute(ACCOUNT_LINKING_SESSION_KEY) != null);
  }

  protected Optional<IamX509AuthenticationCredential> getSavedX509AuthenticationCredential(
      HttpSession session) {
    return Optional.ofNullable(
        (IamX509AuthenticationCredential) session.getAttribute(X509_CREDENTIAL_SESSION_KEY));
  }


  protected Authentication getAccountLinkingSavedAuthentication(HttpSession session) {
    return (Authentication) session.getAttribute(ACCOUNT_LINKING_SESSION_SAVED_AUTHENTICATION);
  }

  protected void saveX509LinkingSuccess(IamX509AuthenticationCredential cred,
      RedirectAttributes attributes) {
    attributes.addFlashAttribute(ACCOUNT_LINKING_DASHBOARD_MESSAGE_KEY,
        String.format("Certificate '%s' linked succesfully", cred.getSubject()));
  }

  protected void saveAccountLinkingSuccess(
      AbstractExternalAuthenticationToken<?> externalAuthenticationToken,
      RedirectAttributes attributes) {

    attributes.addFlashAttribute(ACCOUNT_LINKING_DASHBOARD_MESSAGE_KEY,
        String.format("%s account linked succesfully", externalAuthenticationToken.getName()));

  }

  protected void saveAccountLinkingError(Exception ex, RedirectAttributes attributes) {

    attributes.addFlashAttribute(ACCOUNT_LINKING_DASHBOARD_ERROR_KEY, StringEscapeUtils.escapeHtml(ex.getMessage()));
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
        String.format("%s/%s", ACCOUNT_LINKING_BASE_RESOURCE, type.name()));
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

  protected String mapExternalAuthenticationTypeToExternalAuthnURL(ExternalAuthenticationType type,
      String externalIdpId) {

    String redirectUrl = null;

    switch (type) {
      case OIDC:
        redirectUrl = buildRedirectUrl("/openid_connect_login", "iss", externalIdpId);
        break;

      case SAML:
        redirectUrl = buildRedirectUrl("/saml/login", "idp", externalIdpId);
        break;

      default:
        throw new IllegalArgumentException("Unsupported external authentication type: " + type);
    }

    return redirectUrl;
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

  private String buildRedirectUrl(String baseUrl, String param, String value) {
    String retval = baseUrl;
    if (!Strings.isNullOrEmpty(value)) {
      retval =
          UriComponentsBuilder.fromUriString(baseUrl).queryParam(param, value).build().toString();
    }
    return retval;
  }
}
