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

import java.util.Optional;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.security.crypto.password.PasswordEncoder;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.client.service.ClientUtils;
import it.infn.mw.iam.api.common.client.AuthorizationGrantType;
import it.infn.mw.iam.audit.events.client.ClientUpdatedEvent;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.DashboardProperties;
import it.infn.mw.iam.core.oauth.scope.SystemScopeService;
import it.infn.mw.iam.persistence.model.ClientAuthMethod;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.model.PKCEAlgorithm;

public class DashboardConfigService {

  private static final Logger LOG = LoggerFactory.getLogger(DashboardConfigService.class);

  public static final String DASHBOARD_CLIENT_NAME = "The INDIGO IAM Dashboard";
  public static final String DASHBOARD_CALLBACK = "/ui/api/auth/oauth2/callback/indigo-iam";
  public static final String DASHBOARD_DEV_CALLBACK = "/dev/api/auth/oauth2/callback/indigo-iam";
  public static final String DASHBOARD_DEVCONTAINER_CALLBACK =
      "/devcontainer/api/auth/oauth2/callback/indigo-iam";
  public static final Set<String> DASHBOARD_SCOPES =
      Set.of(SystemScopeService.OPENID_SCOPE, SystemScopeService.OFFLINE_ACCESS_SCOPE, "email",
          "profile", "iam:admin.read", "iam:admin.write", "scim:read", "scim:write");

  private final ClientService clientService;
  private final ClientUtils clientUtils;
  private final PasswordEncoder secretEncoder;
  private final ApplicationEventPublisher eventPublisher;
  private final IamProperties iamProperties;
  private final Environment environment;

  public DashboardConfigService(ClientService clientService, ClientUtils clientUtils,
      PasswordEncoder secretEncoder, ApplicationEventPublisher aep, IamProperties iamProperties,
      Environment environment) {
    this.clientService = clientService;
    this.clientUtils = clientUtils;
    this.secretEncoder = secretEncoder;
    this.eventPublisher = aep;
    this.iamProperties = iamProperties;
    this.environment = environment;
  }

  public boolean isEnabled() {
    return iamProperties.getDashboard().isEnabled();
  }

  public void ensureDashboardClientConfigured() {
    if (!isEnabled()) {
      return;
    }

    DashboardProperties props = iamProperties.getDashboard();
    String clientId = props.getClientId();
    String clientSecret = props.getClientSecret();
    Set<String> redirectUris = getDashboardRedirectUris();

    Optional<ClientDetailsEntity> client = clientService.findClientByClientId(clientId);

    if (client.isEmpty()) {
      LOG.info("Dashboard client does not exist. Creating it...");
      createRecordDashboard(clientId, clientSecret, redirectUris);
    } else {
      LOG.debug("Dashboard client exists. Checking client configuration...");
      reconcileClient(client.get(), clientSecret, redirectUris);
    }
  }

  private Set<String> getDashboardRedirectUris() {
    String baseUrl = iamProperties.getBaseUrl();
    if (environment.acceptsProfiles(Profiles.of("dev"))) {
      return Set.of(baseUrl + DASHBOARD_CALLBACK, baseUrl + DASHBOARD_DEV_CALLBACK,
          baseUrl + DASHBOARD_DEVCONTAINER_CALLBACK);
    }
    return Set.of(baseUrl + DASHBOARD_CALLBACK);
  }

  private void reconcileClient(ClientDetailsEntity client, String configuredSecret,
      Set<String> redirectUris) {

    boolean structuralDrift = hasConfigurationDrift(client, redirectUris);
    boolean secretRotated = hasSecretRotation(client, configuredSecret);

    if (!structuralDrift && !secretRotated) {
      return;
    }
    if (secretRotated) {
      LOG.info("Dashboard client secret rotation detected.");
    }
    if (structuralDrift) {
      LOG.warn("Dashboard client configuration drift detected.");
    }
    updateRecordDashboard(client, configuredSecret, redirectUris, secretRotated);
  }

  private boolean hasSecretRotation(ClientDetailsEntity client, String configuredSecret) {
    return !hasValidClientSecret(client, configuredSecret);
  }

  private boolean hasConfigurationDrift(ClientDetailsEntity client, Set<String> redirectUris) {

    return !hasAllRequiredScopes(client) || !hasValidRedirectUris(client, redirectUris)
        || !hasExpectedGrantTypes(client) || !usesClientSecretBasicAuth(client)
        || !usesPKCES256(client) || !client.isActive();
  }

  private void createRecordDashboard(String clientId, String secret, Set<String> redirectUris) {

    ClientDetailsEntity client = new ClientDetailsEntity();
    clientUtils.setupClientDefaults(client);
    client.setClientId(clientId);
    client.setClientSecret(secretEncoder.encode(secret));
    client.setClientName(DASHBOARD_CLIENT_NAME);
    client.setScope(DASHBOARD_SCOPES);
    client.setTokenEndpointAuthMethod(ClientAuthMethod.SECRET_BASIC);
    client.setAccessTokenValiditySeconds(3600);
    client.setCodeChallengeMethod(PKCEAlgorithm.S256);
    client.setActive(true);
    client.setDynamicallyRegistered(false);
    client.setRedirectUris(redirectUris);
    client.setGrantTypes(Set.of(AuthorizationGrantType.CODE.getGrantType(),
        AuthorizationGrantType.REFRESH_TOKEN.getGrantType()));
    clientService.saveNewClient(client);
  }

  private void updateRecordDashboard(ClientDetailsEntity client, String secret,
      Set<String> redirectUris, boolean secretRotated) {

    client.setScope(DASHBOARD_SCOPES);
    client.setGrantTypes(Set.of(AuthorizationGrantType.CODE.getGrantType(),
        AuthorizationGrantType.REFRESH_TOKEN.getGrantType()));
    client.setCodeChallengeMethod(PKCEAlgorithm.S256);
    if (secretRotated) {
      client.setClientSecret(secretEncoder.encode(secret));
    }
    client.setRedirectUris(redirectUris);
    client.setTokenEndpointAuthMethod(ClientAuthMethod.SECRET_BASIC);
    client.setActive(true);

    ClientDetailsEntity updatedClient = clientService.updateClient(client);
    eventPublisher.publishEvent(new ClientUpdatedEvent(this, updatedClient));
  }

  private boolean hasAllRequiredScopes(ClientDetailsEntity client) {
    return client.getScope() != null && client.getScope().containsAll(DASHBOARD_SCOPES);
  }

  private boolean hasValidClientSecret(ClientDetailsEntity client, String clientSecret) {
    return secretEncoder.matches(clientSecret, client.getClientSecret());
  }

  private boolean hasValidRedirectUris(ClientDetailsEntity client, Set<String> redirectUris) {
    return redirectUris.equals(client.getRedirectUris());
  }

  private boolean hasExpectedGrantTypes(ClientDetailsEntity client) {
    return Set
      .of(AuthorizationGrantType.CODE.getGrantType(),
          AuthorizationGrantType.REFRESH_TOKEN.getGrantType())
      .equals(client.getGrantTypes());
  }

  private boolean usesClientSecretBasicAuth(ClientDetailsEntity client) {
    return ClientAuthMethod.SECRET_BASIC.equals(client.getTokenEndpointAuthMethod());
  }

  private boolean usesPKCES256(ClientDetailsEntity client) {
    return PKCEAlgorithm.S256.equals(client.getCodeChallengeMethod());
  }
}
