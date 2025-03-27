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

import static it.infn.mw.iam.core.oauth.IamOauthRequestParameters.REMEMBER_PARAMETER_KEY;
import static java.lang.String.valueOf;
import static org.mitre.openid.connect.request.ConnectRequestParameters.APPROVED_SITE;
import static org.mitre.openid.connect.request.ConnectRequestParameters.PROMPT;
import static org.mitre.openid.connect.request.ConnectRequestParameters.PROMPT_CONSENT;
import static org.mitre.openid.connect.request.ConnectRequestParameters.PROMPT_SEPARATOR;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.USER_OAUTH_APPROVAL;

import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpSession;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.openid.connect.model.ApprovedSite;
import org.mitre.openid.connect.model.WhitelistedSite;
import org.mitre.openid.connect.service.ApprovedSiteService;
import org.mitre.openid.connect.service.WhitelistedSiteService;
import org.mitre.openid.connect.web.AuthenticationTimeStamper;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.Sets;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
@Component("iamUserApprovalHandler")
public class IamUserApprovalHandler implements UserApprovalHandler {

  private final ClientDetailsEntityService clientDetailsService;
  private final ApprovedSiteService approvedSiteService;
  private final WhitelistedSiteService whitelistedSiteService;
  private final SystemScopeService systemScopeService;
  private final AccountUtils accountUtils;
  private final ClientService clientService;

  public static final String OIDC_AGENT_PREFIX_NAME = "oidc-agent:";

  public IamUserApprovalHandler(ClientDetailsEntityService clientDetailsService,
      ApprovedSiteService approvedSiteService, WhitelistedSiteService whitelistedSiteService,
      SystemScopeService systemScopeService, AccountUtils accountUtils,
      ClientService clientService) {
    this.clientDetailsService = clientDetailsService;
    this.approvedSiteService = approvedSiteService;
    this.whitelistedSiteService = whitelistedSiteService;
    this.systemScopeService = systemScopeService;
    this.accountUtils = accountUtils;
    this.clientService = clientService;
  }

  @Override
  public boolean isApproved(AuthorizationRequest authorizationRequest,
      Authentication userAuthentication) {

    if (authorizationRequest.isApproved()) {
      return true;
    }
    return Boolean
      .parseBoolean(authorizationRequest.getApprovalParameters().get(USER_OAUTH_APPROVAL));
  }

  @Override
  public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest,
      Authentication userAuthentication) {

    String prompt = (String) authorizationRequest.getExtensions().get(PROMPT);
    List<String> prompts = Splitter.on(PROMPT_SEPARATOR).splitToList(Strings.nullToEmpty(prompt));
    if (prompts.contains(PROMPT_CONSENT)) {
      return authorizationRequest;
    }

    String userId = userAuthentication.getName();
    String clientId = authorizationRequest.getClientId();
    Set<String> scopes = authorizationRequest.getScope();

    boolean alreadyApproved = false;

    Collection<ApprovedSite> aps = approvedSiteService.getByClientIdAndUserId(clientId, userId);

    for (ApprovedSite ap : aps) {

      if (!ap.isExpired() && systemScopeService.scopesMatch(ap.getAllowedScopes(), scopes)) {


        ap.setAccessDate(new Date());
        approvedSiteService.save(ap);

        authorizationRequest.getExtensions().put(APPROVED_SITE, valueOf(ap.getId()));
        authorizationRequest.setApproved(true);
        alreadyApproved = true;

        setAuthTime(authorizationRequest);
      }
    }

    if (!alreadyApproved) {
      WhitelistedSite ws = whitelistedSiteService.getByClientId(clientId);
      if (ws != null && systemScopeService.scopesMatch(ws.getAllowedScopes(), scopes)) {

        authorizationRequest.setApproved(true);
        setAuthTime(authorizationRequest);
      }
    }

    return authorizationRequest;
  }

  @Override
  public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest,
      Authentication userAuthentication) {

    String userId = userAuthentication.getName();
    String clientId = authorizationRequest.getClientId();
    ClientDetailsEntity client = clientDetailsService.loadClientByClientId(clientId);
    Map<String, String> approvalParams = authorizationRequest.getApprovalParameters();

    if (!Boolean.parseBoolean(approvalParams.get(USER_OAUTH_APPROVAL))) {
      return authorizationRequest;
    }

    Set<String> requestedScopes = authorizationRequest.getScope();
    Set<String> approvedScopes = Sets.newHashSet();

    // The scope filtering is done by the caller. No more scope filtering is necessary here
    requestedScopes.forEach(rs -> {
      if (systemScopeService.scopesMatch(client.getScope(), Sets.newHashSet(rs))) {
        approvedScopes.add(rs);
      }
    });

    boolean approved = true;
    if (approvedScopes.isEmpty() && !requestedScopes.isEmpty()) {
      approved = false;
    }
    authorizationRequest.setApproved(approved);
    authorizationRequest.setScope(approvedScopes);

    String remember = approvalParams.get(REMEMBER_PARAMETER_KEY);
    if (!Strings.isNullOrEmpty(remember) && !remember.equals("none")) {

      Date timeout = null;
      if (remember.equals("one-hour")) {
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.HOUR, 1);
        timeout = cal.getTime();
      }

      ApprovedSite newSite =
          approvedSiteService.createApprovedSite(clientId, userId, timeout, approvedScopes);
      String newSiteId = newSite.getId().toString();
      authorizationRequest.getExtensions().put(APPROVED_SITE, newSiteId);
    }

    setAuthTime(authorizationRequest);

    IamAccount account = accountUtils.getAuthenticatedUserAccount(userAuthentication).orElseThrow();

    if (client.getClientName().startsWith(OIDC_AGENT_PREFIX_NAME)
        && clientService.findClientOwners(clientId, null).isEmpty()) {
      clientService.linkClientToAccount(client, account);
    }

    return authorizationRequest;
  }

  private void setAuthTime(AuthorizationRequest authorizationRequest) {

    ServletRequestAttributes attr =
        (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();

    HttpSession session = attr.getRequest().getSession();
    if (session == null) {
      return;
    }
    Date authTime = (Date) session.getAttribute(AuthenticationTimeStamper.AUTH_TIMESTAMP);
    if (authTime == null) {
      return;
    }
    authorizationRequest.getExtensions()
      .put(AuthenticationTimeStamper.AUTH_TIMESTAMP, Long.toString(authTime.getTime()));
  }

  @Override
  public Map<String, Object> getUserApprovalRequest(AuthorizationRequest authorizationRequest,
      Authentication userAuthentication) {
    Map<String, Object> model = new HashMap<>();
    model.putAll(authorizationRequest.getRequestParameters());
    return model;
  }

}
