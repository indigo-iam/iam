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

import static it.infn.mw.iam.core.oauth.IamOauthRequestParameters.APPROVAL_PARAMETER_KEY;
import static it.infn.mw.iam.core.oauth.IamOauthRequestParameters.REMEMBER_PARAMETER_KEY;
import static org.mitre.openid.connect.request.ConnectRequestParameters.APPROVED_SITE;
import static org.mitre.openid.connect.request.ConnectRequestParameters.PROMPT;
import static org.mitre.openid.connect.request.ConnectRequestParameters.PROMPT_CONSENT;
import static org.mitre.openid.connect.request.ConnectRequestParameters.PROMPT_SEPARATOR;

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
import org.springframework.beans.factory.annotation.Autowired;
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
import it.infn.mw.iam.api.common.NoSuchAccountError;
import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
@Component("iamUserApprovalHandler")
public class IamUserApprovalHandler implements UserApprovalHandler {
  
  public static final String OIDC_AGENT_PREFIX_NAME = "oidc-agent:";

  @Autowired
  private ClientDetailsEntityService clientDetailsService;

  @Autowired
  private ClientService clientService;

  @Autowired
  private AccountUtils accountUtils;

  @Autowired
  private ApprovedSiteService approvedSiteService;

  @Autowired
  private WhitelistedSiteService whitelistedSiteService;

  @Autowired
  private SystemScopeService systemScopes;

  @Override
  public boolean isApproved(AuthorizationRequest authorizationRequest,
      Authentication userAuthentication) {

    if (authorizationRequest.isApproved()) {
      return true;
    } else {
      // TODO: make parameter name configurable?
      return Boolean
        .parseBoolean(authorizationRequest.getApprovalParameters().get(APPROVAL_PARAMETER_KEY));
    }

  }

  @Override
  public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest,
      Authentication userAuthentication) {

    String userId = userAuthentication.getName();
    String clientId = authorizationRequest.getClientId();

    boolean alreadyApproved = false;

    String prompt = (String) authorizationRequest.getExtensions().get(PROMPT);
    List<String> prompts = Splitter.on(PROMPT_SEPARATOR).splitToList(Strings.nullToEmpty(prompt));
    if (!prompts.contains(PROMPT_CONSENT)) {

      Collection<ApprovedSite> aps = approvedSiteService.getByClientIdAndUserId(clientId, userId);
      for (ApprovedSite ap : aps) {

        if (!ap.isExpired()) {

          if (systemScopes.scopesMatch(ap.getAllowedScopes(), authorizationRequest.getScope())) {

            ap.setAccessDate(new Date());
            approvedSiteService.save(ap);

            String apId = ap.getId().toString();
            authorizationRequest.getExtensions().put(APPROVED_SITE, apId);
            authorizationRequest.setApproved(true);
            alreadyApproved = true;

            setAuthTime(authorizationRequest);
          }
        }
      }

      if (!alreadyApproved) {
        WhitelistedSite ws = whitelistedSiteService.getByClientId(clientId);
        if (ws != null
            && systemScopes.scopesMatch(ws.getAllowedScopes(), authorizationRequest.getScope())) {
          authorizationRequest.setApproved(true);

          setAuthTime(authorizationRequest);
        }
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

    // This must be re-parsed here because SECOAUTH forces us to call things in a strange order
    if (Boolean
      .parseBoolean(authorizationRequest.getApprovalParameters().get(APPROVAL_PARAMETER_KEY))) {

      authorizationRequest.setApproved(true);

      Set<String> allowedScopes = Sets.newHashSet();
      Map<String, String> approvalParams = authorizationRequest.getApprovalParameters();

      Set<String> keys = approvalParams.keySet();

      for (String key : keys) {
        if (key.startsWith("scope_")) {

          String scope = approvalParams.get(key);
          Set<String> approveSet = Sets.newHashSet(scope);

          if (systemScopes.scopesMatch(client.getScope(), approveSet)) {

            allowedScopes.add(scope);
          }

        }
      }

      authorizationRequest.setScope(allowedScopes);

      String remember = authorizationRequest.getApprovalParameters().get(REMEMBER_PARAMETER_KEY);
      if (!Strings.isNullOrEmpty(remember) && !remember.equals("none")) {

        Date timeout = null;
        if (remember.equals("one-hour")) {
          Calendar cal = Calendar.getInstance();
          cal.add(Calendar.HOUR, 1);
          timeout = cal.getTime();
        }

        ApprovedSite newSite =
            approvedSiteService.createApprovedSite(clientId, userId, timeout, allowedScopes);
        String newSiteId = newSite.getId().toString();
        authorizationRequest.getExtensions().put(APPROVED_SITE, newSiteId);
      }

      setAuthTime(authorizationRequest);

      if (isApproved(authorizationRequest, userAuthentication)) {

        IamAccount account = accountUtils.getAuthenticatedUserAccount(userAuthentication)
          .orElseThrow(() -> NoSuchAccountError.forUsername(userAuthentication.getName()));

        if (client.getClientName().startsWith(OIDC_AGENT_PREFIX_NAME)) {
          clientService.linkClientToAccount(client, account);
        }
      }

    }

    return authorizationRequest;

  }

  private void setAuthTime(AuthorizationRequest authorizationRequest) {
    ServletRequestAttributes attr =
        (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
    if (attr != null) {
      HttpSession session = attr.getRequest().getSession();
      if (session != null) {
        Date authTime = (Date) session.getAttribute(AuthenticationTimeStamper.AUTH_TIMESTAMP);
        if (authTime != null) {
          String authTimeString = Long.toString(authTime.getTime());
          authorizationRequest.getExtensions()
            .put(AuthenticationTimeStamper.AUTH_TIMESTAMP, authTimeString);
        }
      }
    }
  }

  @Override
  public Map<String, Object> getUserApprovalRequest(AuthorizationRequest authorizationRequest,
      Authentication userAuthentication) {
    Map<String, Object> model = new HashMap<>();
    model.putAll(authorizationRequest.getRequestParameters());
    return model;
  }


}
