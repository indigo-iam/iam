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

import java.net.URI;
import java.net.URISyntaxException;
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
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.common.NoSuchAccountError;
import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
@Controller
public class IamDeviceEndpointController {

  public static final String URL = "devicecode";
  public static final String USER_URL = "device";

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
  private ClientService clientService;

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
      logger.error("Client asked for " + requestedScopes + " but is allowed " + allowedScopes);
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
      HttpSession session) {

    if (!config.isAllowCompleteDeviceCodeUri() || userCode == null) {
      return "requestUserCode";
    } else {

      return readUserCode(userCode, model, session);
    }
  }

  @PreAuthorize("hasRole('ROLE_USER')")
  @RequestMapping(value = "/" + USER_URL + "/verify", method = RequestMethod.POST)
  public String readUserCode(@RequestParam("user_code") String userCode, ModelMap model,
      HttpSession session) {

    DeviceCode dc = deviceCodeService.lookUpByUserCode(userCode);

    if (dc == null) {
      model.addAttribute("error", "noUserCode");
      return "requestUserCode";
    }

    if (dc.getExpiration() != null && dc.getExpiration().before(new Date())) {
      model.addAttribute("error", "expiredUserCode");
      return "requestUserCode";
    }

    if (dc.isApproved()) {
      model.addAttribute("error", "userCodeAlreadyApproved");
      return "requestUserCode";
    }

    ClientDetailsEntity client = clientEntityService.loadClientByClientId(dc.getClientId());

    model.put("client", client);
    model.put("dc", dc);

    sortScopesForApproval(dc, model);

    AuthorizationRequest authorizationRequest =
        oAuth2RequestFactory.createAuthorizationRequest(dc.getRequestParameters());

    session.setAttribute("authorizationRequest", authorizationRequest);
    session.setAttribute("deviceCode", dc);

    return "approveDevice";
  }

  @PreAuthorize("hasRole('ROLE_USER')")
  @RequestMapping(value = "/" + USER_URL + "/approve", method = RequestMethod.POST)
  public String approveDevice(@RequestParam("user_code") String userCode,
      @RequestParam(value = "user_oauth_approval") Boolean approve, ModelMap model,
      Authentication auth, HttpSession session) {

    AuthorizationRequest authorizationRequest =
        (AuthorizationRequest) session.getAttribute("authorizationRequest");
    DeviceCode dc = (DeviceCode) session.getAttribute("deviceCode");

    if (!dc.getUserCode().equals(userCode)) {
      model.addAttribute("error", "userCodeMismatch");
      return "requestUserCode";
    }

    if (dc.getExpiration() != null && dc.getExpiration().before(new Date())) {
      model.addAttribute("error", "expiredUserCode");
      return "requestUserCode";
    }

    ClientDetailsEntity client = clientEntityService.loadClientByClientId(dc.getClientId());

    model.put("client", client);

    if (!approve) {
      model.addAttribute("approved", false);
      return "deviceApproved";
    }

    OAuth2Request o2req = oAuth2RequestFactory.createOAuth2Request(authorizationRequest);
    OAuth2Authentication o2Auth = new OAuth2Authentication(o2req, auth);

    deviceCodeService.approveDeviceCode(dc, o2Auth);

    sortScopesForApproval(dc, model);

    model.put("approved", true);

    IamAccount account = accountUtils.getAuthenticatedUserAccount(auth)
      .orElseThrow(() -> NoSuchAccountError.forUsername(auth.getName()));

    if (client.getClientName().startsWith("oidc-agent:")) {
      clientService.linkClientToAccount(client, account);
    }

    return "deviceApproved";
  }

  private void checkAuthzGrant(ClientDetailsEntity client) {
    Collection<String> authorizedGrantTypes = client.getAuthorizedGrantTypes();
    if (authorizedGrantTypes != null && !authorizedGrantTypes.isEmpty()
        && !authorizedGrantTypes.contains(DeviceTokenGranter.GRANT_TYPE)) {
      throw new InvalidClientException("Unauthorized grant type: " + DeviceTokenGranter.GRANT_TYPE);
    }
  }

  private void sortScopesForApproval(DeviceCode dc, ModelMap model) {

    Set<SystemScope> scopes = scopeService.fromStrings(dc.getScope());

    Set<SystemScope> sortedScopes = new LinkedHashSet<>(scopes.size());
    Set<SystemScope> systemScopes = scopeService.getAll();

    for (SystemScope s : systemScopes) {
      if (scopes.contains(s)) {
        sortedScopes.add(s);
      }
    }

    sortedScopes.addAll(Sets.difference(scopes, systemScopes));

    model.put("scopes", sortedScopes);

  }

}
