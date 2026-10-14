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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.client.management.service.ClientManagementService;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod;
import it.infn.mw.iam.audit.events.client.ClientUpdatedEvent;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.DashboardProperties;
import it.infn.mw.iam.core.oauth.scope.SystemScopeService;
import it.infn.mw.iam.persistence.model.ClientAuthMethod;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.PKCEAlgorithm;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@Service
public class DashboardConfigService {

  private static final Logger LOG = LoggerFactory.getLogger(DashboardConfigService.class);

  public static final String DASHBOARD_CLIENT_NAME = "The INDIGO IAM Dashboard";
  public static final String DASHBOARD_CALLBACK = "/ui/api/auth/oauth2/callback/indigo-iam";
  public static final Set<String> DASHBOARD_SCOPES =
      Set.of(SystemScopeService.OPENID_SCOPE, SystemScopeService.OFFLINE_ACCESS_SCOPE, "email", "profile",
          "iam:admin.read", "iam:admin.write", "scim:read", "scim:write");

  private final IamClientRepository clientRepository;
  private final ClientManagementService clientService;
  private final ApplicationEventPublisher eventPublisher;
  private final IamProperties iamProperties;

  public DashboardConfigService(IamClientRepository clientRepository,
      ClientManagementService clientService, ApplicationEventPublisher aep,
      IamProperties iamProperties) {
    this.clientService = clientService;
    this.clientRepository = clientRepository;
    this.eventPublisher = aep;
    this.iamProperties = iamProperties;
  }

  public boolean isEnabled() {
    return iamProperties.getDashboard().isEnabled();
  }

  public void init() throws ParseException {
    if (!isEnabled()) {
      return;
    }

    DashboardProperties props = iamProperties.getDashboard();
    String clientId = props.getClientId();
    String clientSecret = props.getClientSecret();
    String redirectUri = iamProperties.getBaseUrl() + DASHBOARD_CALLBACK;

    Optional<ClientDetailsEntity> client = clientRepository.findByClientId(clientId);

    if (client.isEmpty()) {
      LOG.info("Dashboard client does not exist. Creating it.");
      createRecordDashboard(clientId, clientSecret, redirectUri);
      return;
    }

    reconcileClient(client.get(), clientSecret, redirectUri);
  }

  private void reconcileClient(ClientDetailsEntity client, String configuredSecret,
      String redirectUri) {

    boolean structuralDrift = hasConfigurationDrift(client, redirectUri);
    boolean secretRotated = hasSecretRotation(client, configuredSecret);

    if (!structuralDrift && !secretRotated) {
      return;
    }
    if (secretRotated) {
      LOG.info("Dashboard client secret rotation detected.");
    }
    if (structuralDrift) {
      LOG.warn("Dashboard client configuration drift detected. Restoring expected configuration.");
    }

    updateRecordDashboard(client, configuredSecret, redirectUri);
  }

  public static boolean hasSecretRotation(ClientDetailsEntity client, String configuredSecret) {

    return !configuredSecret.equals(client.getClientSecret());
  }

  public static boolean hasConfigurationDrift(ClientDetailsEntity client, String redirectUri) {

    return !hasAllRequiredScopes(client) || !hasValidRedirectUris(client, redirectUri)
        || !supportsAuthorizationCodeGrant(client) || !usesClientSecretBasicAuth(client)
        || !usesPKCES256(client) || !client.isActive();
  }

  public boolean checkRecordConfiguration(ClientDetailsEntity client, String clientSecret,
      String url) {
    return hasAllRequiredScopes(client) && hasValidClientSecret(client, clientSecret)
        && hasValidRedirectUris(client, url) && supportsAuthorizationCodeGrant(client)
        && usesClientSecretBasicAuth(client) && usesPKCES256(client) && client.isActive();
  }

  private void createRecordDashboard(String clientId, String secret, String url)
      throws ParseException {
    RegisteredClientDTO client = new RegisteredClientDTO();
    client.setScope(DASHBOARD_SCOPES);
    client.setClientId(clientId);
    client.setClientName(DASHBOARD_CLIENT_NAME);
    client.setClientSecret(secret);
    client.setTokenEndpointAuthMethod(TokenEndpointAuthenticationMethod.client_secret_basic);
    client.setAccessTokenValiditySeconds(3600);
    client.setCodeChallengeMethod(PKCEAlgorithm.S256);
    client.setActive(true);
    client.setRedirectUris(Set.of(url));
    client.setGrantTypes(Set.of(AuthorizationGrantType.CODE, AuthorizationGrantType.REFRESH_TOKEN));

    clientService.saveNewClient(client);
  }

  private void updateRecordDashboard(ClientDetailsEntity client, String secret, String url) {
    client.setScope(DASHBOARD_SCOPES);
    client.setGrantTypes(Set.of(AuthorizationGrantType.CODE.getGrantType(),
        AuthorizationGrantType.REFRESH_TOKEN.getGrantType()));
    client.setCodeChallengeMethod(PKCEAlgorithm.S256);
    client.setClientSecret(secret);
    client.setRedirectUris(Set.of(url));
    client.setTokenEndpointAuthMethod(ClientAuthMethod.SECRET_BASIC);
    client.setActive(true);

    clientRepository.save(client);
    eventPublisher.publishEvent(new ClientUpdatedEvent(this, client));
  }

  public static boolean hasAllRequiredScopes(ClientDetailsEntity client) {
    return client.getScope() != null && client.getScope().containsAll(DASHBOARD_SCOPES);
  }

  public static boolean hasValidClientSecret(ClientDetailsEntity client, String clientSecret) {
    return clientSecret.equals(client.getClientSecret());
  }

  public static boolean hasValidRedirectUris(ClientDetailsEntity client, String url) {
    return Set.of(url).equals(client.getRedirectUris());
  }

  public static boolean supportsAuthorizationCodeGrant(ClientDetailsEntity client) {
    return Set
      .of(AuthorizationGrantType.CODE.getGrantType(),
          AuthorizationGrantType.REFRESH_TOKEN.getGrantType())
      .equals(client.getGrantTypes());
  }

  public static boolean usesClientSecretBasicAuth(ClientDetailsEntity client) {
    return ClientAuthMethod.SECRET_BASIC.equals(client.getTokenEndpointAuthMethod());
  }

  public static boolean usesPKCES256(ClientDetailsEntity client) {
    return PKCEAlgorithm.S256.equals(client.getCodeChallengeMethod());
  }
}
