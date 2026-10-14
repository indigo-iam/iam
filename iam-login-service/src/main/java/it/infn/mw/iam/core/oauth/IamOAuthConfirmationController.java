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

import static it.infn.mw.iam.core.oauth.IamOAuth2RequestFactory.splitBySpace;
import static it.infn.mw.iam.core.oauth.IamOAuthRequestParameters.APPROVE_AUTHZ_PAGE;
import static it.infn.mw.iam.core.oauth.IamOAuthRequestParameters.AUTHZ_CODE_URL;
import static it.infn.mw.iam.core.oauth.IamOAuthRequestParameters.ERROR_STRING;
import static it.infn.mw.iam.core.oauth.IamOAuthRequestParameters.RESOURCE_KEY;
import static it.infn.mw.iam.core.oauth.IamOAuthRequestParameters.STATE_PARAMETER_KEY;

import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.http.client.utils.URIBuilder;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
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

import it.infn.mw.iam.core.oauth.exceptions.OAuth2ProtocolException;
import it.infn.mw.iam.core.oauth.model.OAuth2ErrorCode;
import it.infn.mw.iam.core.oauth.scope.SystemScopeService;
import it.infn.mw.iam.core.oidc.ConnectRequestParameters;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@SuppressWarnings("deprecation")
@Controller
@SessionAttributes("authorizationRequest")
public class IamOAuthConfirmationController {

  private IamClientRepository clientRepository;

  private SystemScopeService scopeService;

  private RedirectResolver redirectResolver;

  private IamUserApprovalUtils userApprovalUtils;

  public IamOAuthConfirmationController(IamClientRepository clientRepository,
      SystemScopeService scopeService, RedirectResolver redirectResolver,
      IamUserApprovalUtils userApprovalUtils) {

    this.clientRepository = clientRepository;
    this.scopeService = scopeService;
    this.redirectResolver = redirectResolver;
    this.userApprovalUtils = userApprovalUtils;
  }

  @PreAuthorize("hasRole('ROLE_USER')")
  @GetMapping(AUTHZ_CODE_URL)
  public String confimAccess(Map<String, Object> model,
      @ModelAttribute("authorizationRequest") AuthorizationRequest authRequest,
      Authentication authUser, SessionStatus status) {

    String prompt = (String) authRequest.getExtensions().get(ConnectRequestParameters.PROMPT);
    List<String> prompts = Splitter.on(ConnectRequestParameters.PROMPT_SEPARATOR)
      .splitToList(Strings.nullToEmpty(prompt));

    String clientId = authRequest.getClientId();
    if (clientId == null || clientId.isBlank()) {
      throw OAuth2ProtocolException.invalidClient("Invalid null or blank client id");
    }
    ClientDetailsEntity client = clientRepository.findByClientId(clientId)
      .orElseThrow(() -> OAuth2ProtocolException.invalidClient("Client not found"));

    if (prompts.contains("none")) {

      if (prompts.size() > 1) {
        throw OAuth2ProtocolException
          .invalidRequest("The prompt value 'none' cannot be combined with other values");
      }

      String url = redirectResolver.resolveRedirect(authRequest.getRedirectUri(), client);

      try {
        URIBuilder uriBuilder = new URIBuilder(url);

        uriBuilder.addParameter(ERROR_STRING, OAuth2ErrorCode.CONSENT_REQUIRED.value());
        if (!Strings.isNullOrEmpty(authRequest.getState())) {
          uriBuilder.addParameter(STATE_PARAMETER_KEY, authRequest.getState());
        }

        status.setComplete();
        return "redirect:" + uriBuilder;

      } catch (URISyntaxException e) {
        throw OAuth2ProtocolException
          .invalidRequest("Can't build redirect URI for prompt=none: " + e.getMessage());
      }
    }

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

    model.put("client", client);
    model.put("auth_request", authRequest);
    model.put("redirect_uri", authRequest.getRedirectUri());
    model.put("scopes", scopeService.fromStrings(authRequest.getScope()));
    model.put("claims", userApprovalUtils.claimsForScopes(authUser,
        scopeService.fromStrings(authRequest.getScope())));

    Integer count = userApprovalUtils.consentGrantCount(client.getClientId());

    model.put("count", count);
    model.put("gras", userApprovalUtils.isSafeClient(count, client.getCreatedAt()));

    model.put("contacts", userApprovalUtils.getClientContactsAsString(client.getContacts()));

    if (authRequest.getRequestParameters().containsKey(RESOURCE_KEY)) {
      model.put("resources", splitBySpace(authRequest.getRequestParameters().get(RESOURCE_KEY)));
    }

  }

}
