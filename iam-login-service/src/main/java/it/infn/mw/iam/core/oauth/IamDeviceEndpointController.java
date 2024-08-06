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

import static org.mitre.openid.connect.request.ConnectRequestParameters.APPROVED_SITE;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
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
import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.google.common.collect.Sets;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.common.NoSuchAccountError;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopePolicyPDP;
import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
@Controller
public class IamDeviceEndpointController implements IamOauthRequestParameters {

  public static final Logger logger = LoggerFactory.getLogger(IamDeviceEndpointController.class);

  @Autowired
  private ClientDetailsEntityService clientEntityService;

  @Autowired
  private SystemScopeService scopeService;

  @Autowired
  private ConfigurationPropertiesBean config;

  @Autowired
  private DeviceCodeService deviceCodeService;

  @Autowired
  private OAuth2RequestFactory oAuth2RequestFactory;

  @Autowired
  private AccountUtils accountUtils;

  @Autowired
  private ScopePolicyPDP pdp;

  @Autowired
  private IamUserApprovalHandler iamUserApprovalHandler;

  @RequestMapping(value = "/" + URL, method = RequestMethod.POST,
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
      model.put(HttpCodeView.CODE, HttpStatus.BAD_REQUEST);
      model.put(JsonErrorView.ERROR, "invalid_scope");
      return JsonErrorView.VIEWNAME;
    }

    try {
      DeviceCode dc = deviceCodeService.createNewDeviceCode(requestedScopes, client, parameters);

      Map<String, Object> response = new HashMap<>();
      response.put("device_code", dc.getDeviceCode());
      response.put("user_code", dc.getUserCode());
      response.put("verification_uri", config.getIssuer() + USER_URL);
      if (client.getDeviceCodeValiditySeconds() != null) {
        response.put("expires_in", client.getDeviceCodeValiditySeconds());
      }

      if (config.isAllowCompleteDeviceCodeUri()) {
        URI verificationUriComplete = new URIBuilder(config.getIssuer() + USER_URL)
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
  @RequestMapping(value = "/" + USER_URL, method = RequestMethod.GET)
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
  @RequestMapping(value = "/" + USER_URL + "/verify", method = RequestMethod.POST)
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

    IamAccount account = accountUtils.getAuthenticatedUserAccount(authn)
      .orElseThrow(() -> NoSuchAccountError.forUsername(authn.getName()));

    Set<SystemScope> sortedScopes = sortScopesForApproval(dc, account);

    AuthorizationRequest authorizationRequest =
        oAuth2RequestFactory.createAuthorizationRequest(dc.getRequestParameters());

    setAuthzRequestForPreApproval(authorizationRequest, sortedScopes, client.getClientId());
    iamUserApprovalHandler.checkForPreApproval(authorizationRequest, authn);

    if (authorizationRequest.getExtensions().get(APPROVED_SITE) != null) {

      model.addAttribute(APPROVAL_ATTRIBUTE_KEY, true);
      return DEVICE_APPROVED_PAGE;
    }

    model.put("dc", dc);
    model.put("scopes", sortedScopes);

    session.setAttribute("authorizationRequest", authorizationRequest);
    session.setAttribute("deviceCode", dc);

    return APPROVE_DEVICE_PAGE;
  }

  @PreAuthorize("hasRole('ROLE_USER')")
  @RequestMapping(value = "/" + USER_URL + "/approve", method = RequestMethod.POST)
  public String approveDevice(@RequestParam("user_code") String userCode,
      @RequestParam(value = APPROVAL_PARAMETER_KEY) Boolean approve,
      @RequestParam(value = REMEMBER_PARAMETER_KEY, required = false) String remember, ModelMap model,
      Authentication auth, HttpSession session) {

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

    if (!approve) {
      model.addAttribute(APPROVAL_ATTRIBUTE_KEY, false);
      return DEVICE_APPROVED_PAGE;
    }

    ClientDetailsEntity client = clientEntityService.loadClientByClientId(dc.getClientId());

    model.put("client", client);

    OAuth2Request o2req = oAuth2RequestFactory.createOAuth2Request(authorizationRequest);
    OAuth2Authentication o2Auth = new OAuth2Authentication(o2req, auth);

    deviceCodeService.approveDeviceCode(dc, o2Auth);

    IamAccount account = accountUtils.getAuthenticatedUserAccount(auth)
      .orElseThrow(() -> NoSuchAccountError.forUsername(auth.getName()));

    Set<SystemScope> sortedScopes = sortScopesForApproval(dc, account);

    setAuthzRequestAfterApproval(authorizationRequest, remember, approve, sortedScopes);
    iamUserApprovalHandler.updateAfterApproval(authorizationRequest, o2Auth);

    model.put(APPROVAL_ATTRIBUTE_KEY, true);

    return DEVICE_APPROVED_PAGE;
  }


  private Set<SystemScope> sortScopesForApproval(DeviceCode dc, IamAccount account) {

    Set<SystemScope> scopes = scopeService.fromStrings(dc.getScope());

    Set<SystemScope> sortedScopes = new LinkedHashSet<>(scopes.size());
    Set<SystemScope> systemScopes = scopeService.getAll();

    Set<String> filteredScopes = pdp.filterScopes(scopeService.toStrings(scopes), account);

    for (SystemScope s : systemScopes) {
      if (scopeService.fromStrings(filteredScopes).contains(s)) {
        sortedScopes.add(s);
      }
    }

    sortedScopes.addAll(Sets.difference(scopeService.fromStrings(filteredScopes), systemScopes));

    return sortedScopes;

  }

  private void setAuthzRequestForPreApproval(AuthorizationRequest authorizationRequest,
      Set<SystemScope> scopes, String clientId) {

    Collection<String> scopeCollection = new ArrayList<>();
    scopes.forEach(a -> scopeCollection.add(a.getValue()));

    authorizationRequest.setScope(scopeCollection);
    authorizationRequest.setClientId(clientId);
  }

  private void checkAuthzGrant(ClientDetailsEntity client) {
    Collection<String> authorizedGrantTypes = client.getAuthorizedGrantTypes();
    if (authorizedGrantTypes != null && !authorizedGrantTypes.isEmpty()
        && !authorizedGrantTypes.contains(DeviceTokenGranter.GRANT_TYPE)) {
      throw new InvalidClientException("Unauthorized grant type: " + DeviceTokenGranter.GRANT_TYPE);
    }
  }

  private void setAuthzRequestAfterApproval(AuthorizationRequest authorizationRequest,
      String remember, Boolean approve, Set<SystemScope> scopes) {

    Map<String, String> approvalParameters = new HashMap<>();

    approvalParameters.put(REMEMBER_PARAMETER_KEY, remember);
    approvalParameters.put(APPROVAL_PARAMETER_KEY, approve.toString());

    scopes.forEach(s -> approvalParameters.put("scope_" + s.getValue(), s.getValue()));

    authorizationRequest.setClientId(authorizationRequest.getClientId());
    authorizationRequest.setApprovalParameters(approvalParameters);
  }

}
