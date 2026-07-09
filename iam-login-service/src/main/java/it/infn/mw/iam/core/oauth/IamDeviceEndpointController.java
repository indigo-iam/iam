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
import static it.infn.mw.iam.core.oauth.IamOAuthRequestParameters.APPROVAL_ATTRIBUTE_KEY;
import static it.infn.mw.iam.core.oauth.IamOAuthRequestParameters.APPROVE_DEVICE_PAGE;
import static it.infn.mw.iam.core.oauth.IamOAuthRequestParameters.DEVICE_APPROVED_PAGE;
import static it.infn.mw.iam.core.oauth.IamOAuthRequestParameters.ERROR_STRING;
import static it.infn.mw.iam.core.oauth.IamOAuthRequestParameters.REMEMBER_PARAMETER_KEY;
import static it.infn.mw.iam.core.oauth.IamOAuthRequestParameters.REQUEST_USER_CODE_STRING;
import static it.infn.mw.iam.core.oauth.IamOAuthRequestParameters.RESOURCE_KEY;
import static org.mitre.openid.connect.request.ConnectRequestParameters.APPROVED_SITE;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import javax.servlet.http.HttpSession;

import org.apache.http.client.utils.URIBuilder;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.DeviceCode;
import org.mitre.oauth2.model.SystemScope;
import org.mitre.oauth2.service.SystemScopeService;
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
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import it.infn.mw.iam.core.oauth.device.DeviceCodeService;
import it.infn.mw.iam.core.oauth.granters.IamDeviceCodeTokenGranter;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.persistence.repository.IamDeviceCodeRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@SuppressWarnings("deprecation")
@Controller
public class IamDeviceEndpointController {

  public static final String DEVICE_CODE_URL = "devicecode";
  public static final String USER_CODE_URL = "device";

  public static final Logger logger = LoggerFactory.getLogger(IamDeviceEndpointController.class);

  private final Clock clock;
  private final IamClientRepository clientRepository;
  private final SystemScopeService scopeService;
  private final ConfigurationPropertiesBean config;
  private final DeviceCodeService deviceCodeService;
  private final OAuth2RequestFactory oAuth2RequestFactory;
  private final UserApprovalHandler iamUserApprovalHandler;
  private final IamUserApprovalUtils userApprovalUtils;
  private final IamDeviceCodeRepository deviceCodeRepository;
  private final ScopeFilter scopeFilter;

  public IamDeviceEndpointController(Clock clock, IamClientRepository clientRepository,
      SystemScopeService scopeService, ConfigurationPropertiesBean config,
      DeviceCodeService deviceCodeService, OAuth2RequestFactory oAuth2RequestFactory,
      UserApprovalHandler iamUserApprovalHandler, IamUserApprovalUtils userApprovalUtils,
      IamDeviceCodeRepository deviceCodeRepository, ScopeFilter scopeFilter) {
    this.clock = clock;
    this.clientRepository = clientRepository;
    this.scopeService = scopeService;
    this.config = config;
    this.deviceCodeService = deviceCodeService;
    this.oAuth2RequestFactory = oAuth2RequestFactory;
    this.iamUserApprovalHandler = iamUserApprovalHandler;
    this.userApprovalUtils = userApprovalUtils;
    this.deviceCodeRepository = deviceCodeRepository;
    this.scopeFilter = scopeFilter;
  }

  @PostMapping(value = "/" + DEVICE_CODE_URL,
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE)
  public String requestDeviceCode(@RequestParam("client_id") String clientId,
      @RequestParam(required = false) String scope, @RequestParam Map<String, String> parameters,
      ModelMap model) {

    if (clientId == null || clientId.isBlank()) {
      model.put(HttpCodeView.CODE, HttpStatus.BAD_REQUEST);
      return HttpCodeView.VIEWNAME;
    }
    Optional<ClientDetailsEntity> client = clientRepository.findByClientId(clientId);
    if (client.isEmpty()) {
      model.put(HttpCodeView.CODE, HttpStatus.NOT_FOUND);
      return HttpCodeView.VIEWNAME;
    }
    checkAuthzGrant(client.get());

    Set<String> requestedScopes = OAuth2Utils.parseParameterList(scope);
    Set<String> allowedScopes = client.get().getScope();

    if (!scopeService.scopesMatch(allowedScopes, requestedScopes)) {
      logger.error("Client asked for {} but is allowed {}", requestedScopes, allowedScopes);
      model.put(HttpCodeView.CODE, HttpStatus.BAD_REQUEST);
      model.put(JsonErrorView.ERROR, "invalid_scope");
      model.put(JsonErrorView.ERROR_MESSAGE,
          "One or more requested scope is not allowed for client '" + clientId + "'");
      return JsonErrorView.VIEWNAME;
    }

    try {
      DeviceCode dc =
          deviceCodeService.createNewDeviceCode(requestedScopes, client.get(), parameters);

      Map<String, Object> response = new HashMap<>();
      response.put("device_code", dc.getDeviceCode());
      response.put("user_code", dc.getUserCode());
      response.put("verification_uri", config.getIssuer() + USER_CODE_URL);
      if (client.get().getDeviceCodeValiditySeconds() != null) {
        response.put("expires_in", client.get().getDeviceCodeValiditySeconds());
      }

      if (config.isAllowCompleteDeviceCodeUri()) {
        URI verificationUriComplete = new URIBuilder(config.getIssuer() + USER_CODE_URL)
          .addParameter("user_code", dc.getUserCode())
          .build();

        response.put("verification_uri_complete", verificationUriComplete.toString());
      }

      model.put(JsonEntityView.ENTITY, response);


      return JsonEntityView.VIEWNAME;
    } catch (URISyntaxException use) {
      logger
        .error("unable to build verification_uri_complete due to wrong syntax of uri components");
      model.put(HttpCodeView.CODE, HttpStatus.INTERNAL_SERVER_ERROR);

      return HttpCodeView.VIEWNAME;
    }
  }

  @PreAuthorize("hasRole('ROLE_USER')")
  @GetMapping(value = "/" + USER_CODE_URL)
  public String requestUserCode(
      @RequestParam(value = "user_code", required = false) String userCode, ModelMap model,
      HttpSession session, Authentication authn) {

    if (!config.isAllowCompleteDeviceCodeUri() || userCode == null) {
      return REQUEST_USER_CODE_STRING;
    }
    return readUserCode(userCode, model, session, authn);
  }

  @PreAuthorize("hasRole('ROLE_USER')")
  @PostMapping(value = "/" + USER_CODE_URL + "/verify")
  public String readUserCode(@RequestParam("user_code") String userCode, ModelMap model,
      HttpSession session, Authentication authn) {

    Optional<DeviceCode> dc = deviceCodeService.findByUserCode(userCode);

    if (dc.isEmpty()) {
      model.addAttribute(ERROR_STRING, "noUserCode");
      return REQUEST_USER_CODE_STRING;
    }

    Date now = Date.from(clock.instant());
    if (dc.get().getExpiration() != null && dc.get().getExpiration().before(now)) {
      model.addAttribute(ERROR_STRING, "expiredUserCode");
      return REQUEST_USER_CODE_STRING;
    }

    if (dc.get().isApproved()) {
      model.addAttribute(ERROR_STRING, "userCodeAlreadyApproved");
      return REQUEST_USER_CODE_STRING;
    }

    ClientDetailsEntity client = clientRepository.findByClientId(dc.get().getClientId())
      .orElseThrow(() -> new IllegalStateException("Stored device code client id not found"));

    AuthorizationRequest authorizationRequest =
        oAuth2RequestFactory.createAuthorizationRequest(dc.get().getRequestParameters());

    iamUserApprovalHandler.checkForPreApproval(authorizationRequest, authn);

    model.put("client", client);

    Set<String> sortedAndFilteredScopes = userApprovalUtils.sortScopes(
        scopeService.fromStrings(scopeFilter.filterScopes(authorizationRequest.getScope(), authn)));
    dc.get().setScope(sortedAndFilteredScopes);
    deviceCodeRepository.save(dc.get());

    if (authorizationRequest.getExtensions().get(APPROVED_SITE) != null
        || authorizationRequest.isApproved()) {

      OAuth2Request o2req = oAuth2RequestFactory.createOAuth2Request(authorizationRequest);
      OAuth2Authentication o2Auth = new OAuth2Authentication(o2req, authn);

      deviceCodeService.approveDeviceCode(dc.get(), o2Auth);

      model.addAttribute(APPROVAL_ATTRIBUTE_KEY, true);
      return DEVICE_APPROVED_PAGE;
    }

    setModelForConsentPage(model, authn, dc.get(), client);

    session.setAttribute("authorizationRequest", authorizationRequest);
    session.setAttribute("deviceCode", dc.get());

    return APPROVE_DEVICE_PAGE;
  }

  @PreAuthorize("hasRole('ROLE_USER')")
  @PostMapping(value = "/" + USER_CODE_URL + "/approve")
  public String confirmAccess(@RequestParam("user_code") String userCode,
      @RequestParam(value = OAuth2Utils.USER_OAUTH_APPROVAL) Boolean approve, ModelMap model,
      Authentication auth, HttpSession session) {

    AuthorizationRequest authorizationRequest =
        (AuthorizationRequest) session.getAttribute("authorizationRequest");
    DeviceCode dc = (DeviceCode) session.getAttribute("deviceCode");

    if (!dc.getUserCode().equals(userCode)) {
      model.addAttribute(ERROR_STRING, "userCodeMismatch");
      return REQUEST_USER_CODE_STRING;
    }

    if (dc.getExpiration() != null && dc.getExpiration().before(Date.from(clock.instant()))) {
      model.addAttribute(ERROR_STRING, "expiredUserCode");
      return REQUEST_USER_CODE_STRING;
    }

    ClientDetailsEntity client = clientRepository.findByClientId(dc.getClientId())
      .orElseThrow(() -> new IllegalStateException("Stored device code client id not found"));
    model.put("client", client);

    if (Boolean.FALSE.equals(approve) || approve == null) {
      model.addAttribute(APPROVAL_ATTRIBUTE_KEY, false);
      return DEVICE_APPROVED_PAGE;
    }

    OAuth2Request o2req = oAuth2RequestFactory.createOAuth2Request(authorizationRequest);
    OAuth2Authentication o2Auth = new OAuth2Authentication(o2req, auth);

    deviceCodeService.approveDeviceCode(dc, o2Auth);

    setAuthzRequestAfterApproval(authorizationRequest, approve);
    iamUserApprovalHandler.updateAfterApproval(authorizationRequest, auth);

    model.put(APPROVAL_ATTRIBUTE_KEY, true);

    return DEVICE_APPROVED_PAGE;
  }

  private void checkAuthzGrant(ClientDetailsEntity client) {
    Collection<String> authorizedGrantTypes = client.getAuthorizedGrantTypes();
    if (authorizedGrantTypes != null && !authorizedGrantTypes.isEmpty()
        && !authorizedGrantTypes.contains(IamDeviceCodeTokenGranter.GRANT_TYPE)) {
      throw new InvalidClientException(
          "Unauthorized grant type: " + IamDeviceCodeTokenGranter.GRANT_TYPE);
    }
  }

  private void setModelForConsentPage(ModelMap model, Authentication authn, DeviceCode dc,
      ClientDetailsEntity client) {

    Set<SystemScope> scopes = scopeService.fromStrings(dc.getScope());

    model.put("dc", dc);
    model.put("scopes", scopes);
    model.put("claims", userApprovalUtils.claimsForScopes(authn, scopes));

    Integer count = userApprovalUtils.approvedSiteCount(client.getClientId());

    model.put("count", count);
    model.put("gras", userApprovalUtils.isSafeClient(count, client.getCreatedAt()));
    model.put("contacts", userApprovalUtils.getClientContactsAsString(client.getContacts()));

    if (dc.getRequestParameters().containsKey(RESOURCE_KEY)) {
      model.put("resources", splitBySpace(dc.getRequestParameters().get(RESOURCE_KEY)));
    }

    // just for tests validation
    model.put("scope", OAuth2Utils.formatParameterList(dc.getScope()));
  }

  private void setAuthzRequestAfterApproval(AuthorizationRequest authorizationRequest,
      Boolean approve) {

    Map<String, String> approvalParameters = new HashMap<>();

    approvalParameters.put(REMEMBER_PARAMETER_KEY, "none");
    approvalParameters.put(OAuth2Utils.USER_OAUTH_APPROVAL, approve.toString());

    Set<String> scopes = authorizationRequest.getScope();

    scopes.forEach(s -> approvalParameters.put(OAuth2Utils.SCOPE_PREFIX + s, "true"));

    authorizationRequest.setApprovalParameters(approvalParameters);
  }

}
