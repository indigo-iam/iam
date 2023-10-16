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

import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpSession;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.openid.connect.model.ApprovedSite;
import org.mitre.openid.connect.service.ApprovedSiteService;
import org.mitre.openid.connect.token.TofuUserApprovalHandler;
import org.mitre.openid.connect.web.AuthenticationTimeStamper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.google.common.base.Strings;
import com.google.common.collect.Sets;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.common.NoSuchAccountError;
import it.infn.mw.iam.persistence.model.IamAccount;

@Component
public class IamUserApprovalHandler extends TofuUserApprovalHandler {

  @Autowired
  private ApprovedSiteService approvedSiteService;

  @Autowired
  private ClientDetailsEntityService clientDetailsService;

  @Autowired
  private ClientService clientService;

  @Autowired
  private SystemScopeService systemScopes;

  @Autowired
  private AccountUtils accountUtils;

  @Override
  public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest,
      Authentication userAuthentication) {

    String userId = userAuthentication.getName();
    String clientId = authorizationRequest.getClientId();
    ClientDetailsEntity client = clientDetailsService.loadClientByClientId(clientId);

    // This must be re-parsed here because SECOAUTH forces us to call things in a strange order
    if (Boolean
      .parseBoolean(authorizationRequest.getApprovalParameters().get("user_oauth_approval"))) {

      authorizationRequest.setApproved(true);

      // process scopes from user input
      Set<String> allowedScopes = Sets.newHashSet();
      Map<String, String> approvalParams = authorizationRequest.getApprovalParameters();

      Set<String> keys = approvalParams.keySet();

      for (String key : keys) {
        if (key.startsWith("scope_")) {
          // This is a scope parameter from the approval page. The value sent back should
          // be the scope string. Check to make sure it is contained in the client's
          // registered allowed scopes.

          String scope = approvalParams.get(key);
          Set<String> approveSet = Sets.newHashSet(scope);

          // Make sure this scope is allowed for the given client
          if (systemScopes.scopesMatch(client.getScope(), approveSet)) {

            allowedScopes.add(scope);
          }

        }
      }

      // inject the user-allowed scopes into the auth request
      authorizationRequest.setScope(allowedScopes);

      // Only store an ApprovedSite if the user has checked "remember this decision":
      String remember = authorizationRequest.getApprovalParameters().get("remember");
      if (!Strings.isNullOrEmpty(remember) && !remember.equals("none")) {

        Date timeout = null;
        if (remember.equals("one-hour")) {
          // set the timeout to one hour from now
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

      IamAccount account = accountUtils.getAuthenticatedUserAccount(userAuthentication)
        .orElseThrow(() -> NoSuchAccountError.forUsername(userAuthentication.getName()));;

      if (client.getClientName().startsWith("oidc-agent")) {
        clientService.linkClientToAccount(client, account);
      }

    }

    return authorizationRequest;
  }

  private void setAuthTime(AuthorizationRequest authorizationRequest) {
    // Get the session auth time, if we have it, and store it in the request
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

}
