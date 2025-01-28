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
package it.infn.mw.iam.core.oauth;

import static it.infn.mw.iam.core.oauth.IamOauthRequestParameters.APPROVE_AUTHZ_PAGE;
import static it.infn.mw.iam.core.oauth.IamOauthRequestParameters.AUTHZ_CODE_URL;
import static it.infn.mw.iam.core.oauth.IamOauthRequestParameters.ERROR_STRING;
import static it.infn.mw.iam.core.oauth.IamOauthRequestParameters.STATE_PARAMETER_KEY;
import static org.mitre.openid.connect.request.ConnectRequestParameters.PROMPT;
import static org.mitre.openid.connect.request.ConnectRequestParameters.PROMPT_SEPARATOR;

import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.http.client.utils.URIBuilder;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.openid.connect.view.HttpCodeView;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.endpoint.RedirectResolver;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;

import com.google.common.base.Splitter;
import com.google.common.base.Strings;


@SuppressWarnings("deprecation")
@Controller
@SessionAttributes("authorizationRequest")
public class IamOAuthConfirmationController {

  @Autowired
  private ClientDetailsEntityService clientService;

  @Autowired
  private SystemScopeService scopeService;

  @Autowired
  private RedirectResolver redirectResolver;

  @Autowired
  private IamUserApprovalUtils userApprovalUtils;

  private static final Logger logger =
      LoggerFactory.getLogger(IamOAuthConfirmationController.class);


  @PreAuthorize("hasRole('ROLE_USER')")
  @GetMapping(AUTHZ_CODE_URL)
  public String confimAccess(Map<String, Object> model,
      @ModelAttribute("authorizationRequest") AuthorizationRequest authRequest,
      Authentication authUser, SessionStatus status) {

    String prompt = (String) authRequest.getExtensions().get(PROMPT);
    List<String> prompts = Splitter.on(PROMPT_SEPARATOR).splitToList(Strings.nullToEmpty(prompt));
    ClientDetailsEntity client = null;

    try {
      client = clientService.loadClientByClientId(authRequest.getClientId());
    } catch (OAuth2Exception e) {
      logger.error("confirmAccess: OAuth2Exception was thrown when attempting to load client", e);
      model.put(HttpCodeView.CODE, HttpStatus.BAD_REQUEST);
      return HttpCodeView.VIEWNAME;
    } catch (IllegalArgumentException e) {
      logger.error(
          "confirmAccess: IllegalArgumentException was thrown when attempting to load client", e);
      model.put(HttpCodeView.CODE, HttpStatus.BAD_REQUEST);
      return HttpCodeView.VIEWNAME;
    }

    if (client == null) {
      logger.error("confirmAccess: could not find client {}", authRequest.getClientId());
      model.put(HttpCodeView.CODE, HttpStatus.NOT_FOUND);
      return HttpCodeView.VIEWNAME;
    }

    if (prompts.contains("none")) {

      String url = redirectResolver.resolveRedirect(authRequest.getRedirectUri(), client);

      try {
        URIBuilder uriBuilder = new URIBuilder(url);

        uriBuilder.addParameter(ERROR_STRING, "interaction_required");
        if (!Strings.isNullOrEmpty(authRequest.getState())) {
          uriBuilder.addParameter(STATE_PARAMETER_KEY, authRequest.getState());
        }

        status.setComplete();
        return "redirect:" + uriBuilder.toString();

      } catch (URISyntaxException e) {
        logger.error("Can't build redirect URI for prompt=none, sending error instead", e);
        model.put("code", HttpStatus.FORBIDDEN);
        return HttpCodeView.VIEWNAME;
      }
    }

    model.put("client", client);

    // the authorization request already contains PDP filtered
    // scopes among the request parameters due to the
    // IamOAuth2RequestFactory.createAuthorizationRequest() object
    Set<String> scopes =
        OAuth2Utils.parseParameterList(authRequest.getRequestParameters().get("scope"));
    scopes = userApprovalUtils.sortScopes(scopeService.fromStrings(scopes));

    authRequest.setScope(scopes);

    setModelForConsentPage(model, authRequest, authUser, client);

    return APPROVE_AUTHZ_PAGE;
  }

  private void setModelForConsentPage(Map<String, Object> model, AuthorizationRequest authRequest,
      Authentication authUser, ClientDetailsEntity client) {

    model.put("auth_request", authRequest);
    model.put("redirect_uri", authRequest.getRedirectUri());
    model.put("scopes", scopeService.fromStrings(authRequest.getScope()));
    model.put("claims", userApprovalUtils.claimsForScopes(authUser,
        scopeService.fromStrings(authRequest.getScope())));

    Integer count = userApprovalUtils.approvedSiteCount(client.getClientId());

    model.put("count", count);
    model.put("gras", userApprovalUtils.isSafeClient(count, client.getCreatedAt()));

    model.put("contacts", userApprovalUtils.getClientContactsAsString(client.getContacts()));

  }

}
