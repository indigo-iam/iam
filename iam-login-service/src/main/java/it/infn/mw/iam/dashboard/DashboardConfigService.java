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

import java.text.ParseException;
import java.util.Optional;
import java.util.Set;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.PKCEAlgorithm;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.client.management.service.DefaultClientManagementService;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.DashboardProperties;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod;

@Service
public class DashboardConfigService {

  private static final Logger LOG = LoggerFactory.getLogger(DashboardConfigService.class);

  private static final String DASHBOARD_CALLBACK = "/ui/api/auth/oauth2/callback/indigo-iam";
  private static final Set<String> DASHBOARD_SCOPES = Set.of(SystemScopeService.OPENID_SCOPE,
      SystemScopeService.OFFLINE_ACCESS, "email",
      "profile", "iam:admin.read", "iam:admin.write", "scim:read", "scim:write");

  private final IamClientRepository clientRepository;
  private final DefaultClientManagementService clientService;
  private final IamProperties iamProperties;

  public DashboardConfigService(
      IamClientRepository clientRepository,
      DefaultClientManagementService clientService,
      IamProperties iamProperties) {
    this.clientService = clientService;
    this.clientRepository = clientRepository;
    this.iamProperties = iamProperties;
  }

  public boolean isEnabled() {
    return iamProperties.getDashboard().isEnabled();
  }

  public boolean init() {
    DashboardProperties dashboardProperties = iamProperties.getDashboard();
    String iamUrl = iamProperties.getBaseUrl();
    String clientId = dashboardProperties.getClientId();
    String clientSecret = dashboardProperties.getClientSecret();
    String url = iamUrl + DASHBOARD_CALLBACK;
    Optional<ClientDetailsEntity> dashboardRecord = clientRepository.findByClientId(clientId);

    if (!dashboardRecord.isPresent()) {
      LOG.info("Dashboard client does not exist and it will be created.");
      try {
        createRecordDashboard(clientId, clientSecret, url);
        return true;
      } catch (Exception e) {
        LOG.error("Error saving dashboard client: {}", e.getMessage());
        return false;
      }
    }

    ClientDetailsEntity client = dashboardRecord.get();
    boolean isValid = checkRecordConfiguration(client, clientSecret, url);
    if (!isValid) {
      LOG.warn("Changes on default dashboard client configuration found: restoring expected configuration.");
      updateRecordDashboard(client, clientSecret, url);
    }
    return true;
  }

  public boolean checkRecordConfiguration(ClientDetailsEntity client, String clientSecret, String url) {
    return hasAllRequiredScopes(client)
        && hasValidClientSecret(client, clientSecret)
        && hasValidRedirectUris(client, url)
        && supportsAuthorizationCodeGrant(client)
        && usesClientSecretBasicAuth(client)
        && usesPKCES256(client);
  }

  private void createRecordDashboard(String clientId, String secret, String url) throws ParseException {
    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setScope(DASHBOARD_SCOPES);
    client.setClientId(clientId);
    client.setClientName("dashboard");
    client.setClientSecret(secret);
    client.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.client_secret_basic);
    client.setAccessTokenValiditySeconds(3600);
    client.setCodeChallengeMethod(PKCEAlgorithm.S256.toString());
    client.setActive(true);
    client.setRedirectUris(Set.of(url));
    client.setGrantTypes(Set.of(AuthorizationGrantType.CODE, AuthorizationGrantType.REFRESH_TOKEN));

    clientService.saveNewClient(client);
  }

  private void updateRecordDashboard(ClientDetailsEntity client, String secret, String url) {
    client.setScope(DASHBOARD_SCOPES);
    client.setGrantTypes(
        Set.of(AuthorizationGrantType.CODE.getGrantType(), AuthorizationGrantType.REFRESH_TOKEN.getGrantType()));
    client.setCodeChallengeMethod(PKCEAlgorithm.S256);
    client.setClientSecret(secret);
    client.setRedirectUris(Set.of(url));
    client.setTokenEndpointAuthMethod(AuthMethod.SECRET_BASIC);

    clientRepository.save(client);
  }

  private boolean hasAllRequiredScopes(ClientDetailsEntity client) {
    return client.getScope().containsAll(DASHBOARD_SCOPES);
  }

  private boolean hasValidClientSecret(ClientDetailsEntity client, String clientSecret) {
    return client.getClientSecret().equals(clientSecret);
  }

  private boolean hasValidRedirectUris(ClientDetailsEntity client, String url) {
    return client.getRedirectUris().equals(Set.of(url));
  }

  private boolean supportsAuthorizationCodeGrant(ClientDetailsEntity client) {
    return client.getGrantTypes().equals(
        Set.of(AuthorizationGrantType.CODE.getGrantType(), AuthorizationGrantType.REFRESH_TOKEN.getGrantType()));
  }

  private boolean usesClientSecretBasicAuth(ClientDetailsEntity client) {
    return client.getTokenEndpointAuthMethod().equals(AuthMethod.SECRET_BASIC);
  }

  private boolean usesPKCES256(ClientDetailsEntity client) {
    return client.getCodeChallengeMethod().getName().equals(PKCEAlgorithm.S256.toString());
  }
}
