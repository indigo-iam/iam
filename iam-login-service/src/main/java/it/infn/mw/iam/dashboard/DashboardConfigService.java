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

package it.infn.mw.iam.dashboard;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import javax.annotation.PostConstruct;
import org.springframework.transaction.annotation.Transactional;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.PKCEAlgorithm;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.client.management.service.DefaultClientManagementService;
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.config.IamProperties.DashboardProperties;
import it.infn.mw.iam.core.oauth.scope.pdp.DefaultScopeFilter;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod;

import com.beust.jcommander.internal.Sets;

@Service
public class DashboardConfigService {

  private static final Logger LOG = LoggerFactory.getLogger(DashboardConfigService.class);

  private static final String DASHBOARD_CALLBACK = "/ui/api/auth/oauth2/callback/indigo-iam";
  Set<String> dashboardScopes = Set.of(SystemScopeService.OPENID_SCOPE, SystemScopeService.OFFLINE_ACCESS, "email",
      "profile", "iam:admin.read", "iam:admin.write", "scim:read", "scim:write");

  private final IamClientRepository iamClientDetailsRepository;
  private final DefaultClientManagementService clientService;

  public DashboardConfigService(IamClientRepository iamClientDetailsRepository,
      DefaultClientManagementService clientService) {
    this.clientService = clientService;
    this.iamClientDetailsRepository = iamClientDetailsRepository;
  }

  @Transactional
  public boolean initDashboardClient(DashboardProperties dashboardProperties, String iamUrl) throws java.text.ParseException {
    String clientId = dashboardProperties.getClientId();
    String clientSecret = dashboardProperties.getClientSecret();
    String url = iamUrl + DASHBOARD_CALLBACK;

    Optional<ClientDetailsEntity> test = iamClientDetailsRepository.findByClientId(clientId);

    if (test.isPresent()) {
      ClientDetailsEntity client = test.get();

      boolean isConfigured = checkRecordConfiguration(test.get(), clientSecret, url);
      if (!isConfigured) {
        LOG.warn("The record is not properly configured. Updating Dashboard client.");
        client.setScope(dashboardScopes);
        client.setGrantTypes(Set.of(AuthorizationGrantType.CODE.getGrantType(), AuthorizationGrantType.REFRESH_TOKEN.getGrantType()));
        client.setCodeChallengeMethod(PKCEAlgorithm.S256);
        client.setRedirectUris(Set.of(url));
        client.setTokenEndpointAuthMethod(AuthMethod.SECRET_BASIC);

        iamClientDetailsRepository.save(client);
      }
      return true;
    } else {
      LOG.info("The client record for dashboard does not exist. Creating record with default configuration...");
      RegisteredClientDTO client = new RegisteredClientDTO();
      Set<String> clientScopes = Sets.newHashSet();
      clientScopes.add(StandardClaimNames.PROFILE);
      clientScopes.add(StandardClaimNames.EMAIL);
      clientScopes.add(DefaultScopeFilter.ADMIN_SCOPES.toString());

      client.setScope(clientScopes);
      client.setClientId(clientId);
      client.setClientName("dashboard");
      client.setClientSecret(clientSecret);
      client.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.client_secret_basic);
      client.setAccessTokenValiditySeconds(3600);
      client.setCodeChallengeMethod(PKCEAlgorithm.S256.toString());
      client.setActive(true);
      client.setRedirectUris(Set.of(url));
      client.setGrantTypes(Set.of(AuthorizationGrantType.CODE, AuthorizationGrantType.REFRESH_TOKEN));

      try {
        clientService.saveNewClient(client);
      } catch (Exception e) {
        LOG.error("Error saving dashboard client: " + e.getMessage());
        return false;
      }
      return true;
    }
  }

  public boolean checkRecordConfiguration(ClientDetailsEntity client, String clientSecret, String url) {
    return hasAllRequiredScopes(client)
        && hasValidClientSecret(client, clientSecret)
        && hasValidRedirectUris(client, url)
        && supportsAuthorizationCodeGrant(client)
        && usesClientSecretBasicAuth(client)
        && usesPKCES256(client);
  }

  private boolean hasAllRequiredScopes(ClientDetailsEntity client) {
    return client.getScope().containsAll(dashboardScopes);
  }

  private boolean hasValidClientSecret(ClientDetailsEntity client, String clientSecret) {
    return client.getClientSecret().equals(clientSecret);
  }

  private boolean hasValidRedirectUris(ClientDetailsEntity client, String url) {
    return client.getRedirectUris().containsAll(Set.of(url));
  }

  private boolean supportsAuthorizationCodeGrant(ClientDetailsEntity client) {
    return client.getGrantTypes().containsAll(
        Set.of(AuthorizationGrantType.CODE.getGrantType(), AuthorizationGrantType.REFRESH_TOKEN.getGrantType()));
  }

  private boolean usesClientSecretBasicAuth(ClientDetailsEntity client) {
    return client.getTokenEndpointAuthMethod().equals(AuthMethod.SECRET_BASIC);
  }

  private boolean usesPKCES256(ClientDetailsEntity client) {
    return client.getCodeChallengeMethod().getName().equals(PKCEAlgorithm.S256.toString());
  }
}
