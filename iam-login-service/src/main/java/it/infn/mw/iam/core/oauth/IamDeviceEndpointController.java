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

import static it.infn.mw.iam.core.oauth.IamOauthRequestParameters.APPROVAL_ATTRIBUTE_KEY;
import static it.infn.mw.iam.core.oauth.IamOauthRequestParameters.APPROVE_DEVICE_PAGE;
import static it.infn.mw.iam.core.oauth.IamOauthRequestParameters.DEVICE_APPROVED_PAGE;
import static it.infn.mw.iam.core.oauth.IamOauthRequestParameters.DEVICE_CODE_URL;
import static it.infn.mw.iam.core.oauth.IamOauthRequestParameters.ERROR_STRING;
import static it.infn.mw.iam.core.oauth.IamOauthRequestParameters.REMEMBER_PARAMETER_KEY;
import static it.infn.mw.iam.core.oauth.IamOauthRequestParameters.REQUEST_USER_CODE_STRING;
import static it.infn.mw.iam.core.oauth.IamOauthRequestParameters.USER_CODE_URL;
import static org.mitre.openid.connect.request.ConnectRequestParameters.APPROVED_SITE;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpSession;

import org.apache.http.client.utils.URIBuilder;
import org.mitre.oauth2.exception.DeviceCodeCreationException;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.DeviceCode;
import org.mitre.oauth2.model.SystemScope;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.DeviceCodeService;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.oauth2.token.DeviceTokenGranter;
import org.mitre.openid.connect.config.ConfigurationPropertiesBean;
import org.mitre.openid.connect.view.HttpCodeView;
import org.mitre.openid.connect.view.JsonEntityView;
import org.mitre.openid.connect.view.JsonErrorView;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.common.error.NoSuchAccountError;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopePolicyPDP;
import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
@Controller
public class IamDeviceEndpointController {

  public static final Logger logger = LoggerFactory.getLogger(IamDeviceEndpointController.class);

  private final ClientDetailsEntityService clientEntityService;
  private final SystemScopeService scopeService;
  private final ConfigurationPropertiesBean config;
  private final DeviceCodeService deviceCodeService;
  private final DefaultOAuth2RequestFactory oAuth2RequestFactory;
  private final UserApprovalHandler iamUserApprovalHandler;
  private final IamUserApprovalUtils userApprovalUtils;
  private final AccountUtils accountUtils;
  private final ScopePolicyPDP pdp;

  public IamDeviceEndpointController(ClientDetailsEntityService clientEntityService,
      SystemScopeService scopeService, ConfigurationPropertiesBean config,
      DeviceCodeService deviceCodeService, DefaultOAuth2RequestFactory oAuth2RequestFactory,
      UserApprovalHandler iamUserApprovalHandler, IamUserApprovalUtils userApprovalUtils,
      AccountUtils accountUtils, ScopePolicyPDP pdp) {
    this.clientEntityService = clientEntityService;
    this.scopeService = scopeService;
    this.config = config;
    this.deviceCodeService = deviceCodeService;
    this.oAuth2RequestFactory = oAuth2RequestFactory;
    this.iamUserApprovalHandler = iamUserApprovalHandler;
    this.userApprovalUtils = userApprovalUtils;
    this.accountUtils = accountUtils;
    this.pdp = pdp;
  }

  @PostMapping(value = "/" + DEVICE_CODE_URL,
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE)
  public String requestDeviceCode(@RequestParam("client_id") String clientId,
      @RequestParam(name = "scope", required = false) String scope, Map<String, String> parameters,
      ModelMap model) {

    ClientDetailsEntity client;
    try {
      client = clientEntityService.loadClientByClientId(clientId);
      checkAuthzGrant(client);

    } catch (IllegalArgumentException e) {
      logger.error("IllegalArgumentException was thrown when attempting to load client", e);
      model.put(HttpCodeView.CODE, HttpStatus.BAD_REQUEST);
      return HttpCodeView.VIEWNAME;
    }

    Set<String> requestedScopes = OAuth2Utils.parseParameterList(scope);
    Set<String> allowedScopes = client.getScope();

    if (!scopeService.scopesMatch(allowedScopes, requestedScopes)) {
      logger.error("Client asked for {} but is allowed {}", requestedScopes, allowedScopes);
      throw new InvalidScopeException(
          String.format("Scope not allowed for client '%s'", client.getClientId()));
    }

    try {
      DeviceCode dc = deviceCodeService.createNewDeviceCode(requestedScopes, client, parameters);

      Map<String, Object> response = new HashMap<>();
      response.put("device_code", dc.getDeviceCode());
      response.put("user_code", dc.getUserCode());
      response.put("verification_uri", config.getIssuer() + USER_CODE_URL);
      if (client.getDeviceCodeValiditySeconds() != null) {
        response.put("expires_in", client.getDeviceCodeValiditySeconds());
      }

      if (config.isAllowCompleteDeviceCodeUri()) {
        URI verificationUriComplete = new URIBuilder(config.getIssuer() + USER_CODE_URL)
          .addParameter("user_code", dc.getUserCode())
          .build();

        response.put("verification_uri_complete", verificationUriComplete.toString());
      }

      model.put(JsonEntityView.ENTITY, response);


      return JsonEntityView.VIEWNAME;
    } catch (DeviceCodeCreationException dcce) {

      model.put(HttpCodeView.CODE, HttpStatus.BAD_REQUEST);
      model.put(JsonErrorView.ERROR, dcce.getError());
      model.put(JsonErrorView.ERROR_MESSAGE, dcce.getMessage());

      return JsonErrorView.VIEWNAME;
    } catch (URISyntaxException use) {
      logger
        .error("unable to build verification_uri_complete due to wrong syntax of uri components");
      model.put(HttpCodeView.CODE, HttpStatus.INTERNAL_SERVER_ERROR);

      return HttpCodeView.VIEWNAME;
    }

  }

  @PreAuthorize("hasRole('ROLE_USER')")
  @GetMapping("/" + USER_CODE_URL)
  public String requestUserCode(
      @RequestParam(value = "user_code", required = false) String userCode, ModelMap model,
      HttpSession session, Authentication authn) {

    if (!config.isAllowCompleteDeviceCodeUri() || userCode == null) {
      return REQUEST_USER_CODE_STRING;
    } else {

      return readUserCode(userCode, model, session, authn);
    }
  }

  @PreAuthorize("hasRole('ROLE_USER')")
  @PostMapping("/" + USER_CODE_URL + "/verify")
  public String readUserCode(@RequestParam("user_code") String userCode, ModelMap model,
      HttpSession session, Authentication authn) {

    DeviceCode dc = deviceCodeService.lookUpByUserCode(userCode);

    if (dc == null) {
      model.addAttribute(ERROR_STRING, "noUserCode");
      return REQUEST_USER_CODE_STRING;
    }

    if (dc.getExpiration() != null && dc.getExpiration().before(new Date())) {
      model.addAttribute(ERROR_STRING, "expiredUserCode");
      return REQUEST_USER_CODE_STRING;
    }

    if (dc.isApproved()) {
      model.addAttribute(ERROR_STRING, "userCodeAlreadyApproved");
      return REQUEST_USER_CODE_STRING;
    }

    ClientDetailsEntity client = clientEntityService.loadClientByClientId(dc.getClientId());

    model.put("client", client);

    AuthorizationRequest authorizationRequest =
        oAuth2RequestFactory.createAuthorizationRequest(dc.getRequestParameters());

    Set<String> filteredScopes = filterScopes(scopeService.fromStrings(dc.getScope()), authn);
    filteredScopes = userApprovalUtils.sortScopes(scopeService.fromStrings(filteredScopes));

    authorizationRequest.setScope(filteredScopes);
    authorizationRequest.setClientId(client.getClientId());

    iamUserApprovalHandler.checkForPreApproval(authorizationRequest, authn);

    OAuth2Request o2req = oAuth2RequestFactory.createOAuth2Request(authorizationRequest);
    OAuth2Authentication o2Auth = new OAuth2Authentication(o2req, authn);

    deviceCodeService.approveDeviceCode(dc, o2Auth);

    if (authorizationRequest.getExtensions().get(APPROVED_SITE) != null
        || authorizationRequest.isApproved()) {

      model.addAttribute(APPROVAL_ATTRIBUTE_KEY, true);
      return DEVICE_APPROVED_PAGE;
    }

    setModelForConsentPage(model, authn, dc, filteredScopes, client);

    session.setAttribute("authorizationRequest", authorizationRequest);
    session.setAttribute("deviceCode", dc);

    return APPROVE_DEVICE_PAGE;
  }

  @PreAuthorize("hasRole('ROLE_USER')")
  @PostMapping("/" + USER_CODE_URL + "/approve")
  public String approveDevice(@RequestParam("user_code") String userCode,
      @RequestParam(value = OAuth2Utils.USER_OAUTH_APPROVAL) Boolean approve,
      @RequestParam(value = REMEMBER_PARAMETER_KEY, required = false) String remember,
      ModelMap model, Authentication auth, HttpSession session) {

    AuthorizationRequest authorizationRequest =
        (AuthorizationRequest) session.getAttribute("authorizationRequest");
    DeviceCode dc = (DeviceCode) session.getAttribute("deviceCode");

    if (!dc.getUserCode().equals(userCode)) {
      model.addAttribute(ERROR_STRING, "userCodeMismatch");
      return REQUEST_USER_CODE_STRING;
    }

    if (dc.getExpiration() != null && dc.getExpiration().before(new Date())) {
      model.addAttribute(ERROR_STRING, "expiredUserCode");
      return REQUEST_USER_CODE_STRING;
    }

    ClientDetailsEntity client = clientEntityService.loadClientByClientId(dc.getClientId());
    model.put("client", client);

    if (Boolean.FALSE.equals(approve)) {
      model.addAttribute(APPROVAL_ATTRIBUTE_KEY, false);
      return DEVICE_APPROVED_PAGE;
    }

    OAuth2Request o2req = oAuth2RequestFactory.createOAuth2Request(authorizationRequest);
    OAuth2Authentication o2Auth = new OAuth2Authentication(o2req, auth);

    setAuthzRequestAfterApproval(authorizationRequest, remember, approve);
    iamUserApprovalHandler.updateAfterApproval(authorizationRequest, o2Auth);

    model.put(APPROVAL_ATTRIBUTE_KEY, true);

    return DEVICE_APPROVED_PAGE;
  }

  private void checkAuthzGrant(ClientDetailsEntity client) {
    Collection<String> authorizedGrantTypes = client.getAuthorizedGrantTypes();
    if (authorizedGrantTypes != null && !authorizedGrantTypes.isEmpty()
        && !authorizedGrantTypes.contains(DeviceTokenGranter.GRANT_TYPE)) {
      throw new InvalidClientException("Unauthorized grant type: " + DeviceTokenGranter.GRANT_TYPE);
    }
  }

  private Set<String> filterScopes(Set<SystemScope> scopes, Authentication authentication) {

    IamAccount account = accountUtils.getAuthenticatedUserAccount(authentication)
      .orElseThrow(() -> NoSuchAccountError.forUsername(authentication.getName()));

    return pdp.filterScopes(scopeService.toStrings(scopes), account);
  }

  private void setModelForConsentPage(ModelMap model, Authentication authn, DeviceCode dc,
      Set<String> scopes, ClientDetailsEntity client) {

    model.put("dc", dc);
    model.put("scopes", scopeService.fromStrings(scopes));
    model.put("claims", userApprovalUtils.claimsForScopes(authn, scopeService.fromStrings(scopes)));

    Integer count = userApprovalUtils.approvedSiteCount(client.getClientId());

    model.put("count", count);
    model.put("gras", userApprovalUtils.isSafeClient(count, client.getCreatedAt()));
    model.put("contacts", userApprovalUtils.getClientContactsAsString(client.getContacts()));

    // just for tests validation
    model.put("scope", OAuth2Utils.formatParameterList(scopes));
  }

  private void setAuthzRequestAfterApproval(AuthorizationRequest authorizationRequest,
      String remember, Boolean approve) {

    Map<String, String> approvalParameters = new HashMap<>();

    approvalParameters.put(REMEMBER_PARAMETER_KEY, remember);
    approvalParameters.put(OAuth2Utils.USER_OAUTH_APPROVAL, approve.toString());

    Set<String> scopes = authorizationRequest.getScope();

    scopes.forEach(s -> approvalParameters.put(OAuth2Utils.SCOPE_PREFIX + s, "true"));

    authorizationRequest.setApprovalParameters(approvalParameters);
  }

}
