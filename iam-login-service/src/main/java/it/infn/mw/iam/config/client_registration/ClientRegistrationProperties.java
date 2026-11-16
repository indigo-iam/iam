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
package it.infn.mw.iam.config.client_registration;

import static it.infn.mw.iam.api.common.client.AuthorizationGrantType.CLIENT_CREDENTIALS;
import static it.infn.mw.iam.api.common.client.AuthorizationGrantType.PASSWORD;
import static it.infn.mw.iam.api.common.client.AuthorizationGrantType.TOKEN_EXCHANGE;
import static it.infn.mw.iam.config.client_registration.ClientRegistrationProperties.ClientRegistrationAuthorizationPolicy.ANYONE;
import static it.infn.mw.iam.config.client_registration.ClientRegistrationProperties.GrantTypes.DEFAULT_FORBIDDEN_FOR_ANONYMOUS_CLIENTS;
import static it.infn.mw.iam.config.client_registration.ClientRegistrationProperties.GrantTypes.DEFAULT_FORBIDDEN_FOR_USER_CLIENTS;

import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.validation.constraints.NotNull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import it.infn.mw.iam.api.common.client.AuthorizationGrantType;

@ConfigurationProperties("client-registration")
@Configuration
public class ClientRegistrationProperties {

  private static final Logger LOG = LoggerFactory.getLogger(ClientRegistrationProperties.class);

  public static class ClientDefaultsProperties {

    @NotNull(message = "Provide a default access token lifetime")
    private int defaultAccessTokenValiditySeconds;
    @NotNull(message = "Provide a default id token lifetime")
    private int defaultIdTokenValiditySeconds;
    @NotNull(message = "Provide a default device code lifetime")
    private int defaultDeviceCodeValiditySeconds;
    @NotNull(message = "Provide a default refresh token lifetime")
    private int defaultRefreshTokenValiditySeconds;

    public int getDefaultAccessTokenValiditySeconds() {
      return defaultAccessTokenValiditySeconds;
    }

    public void setDefaultAccessTokenValiditySeconds(int defaultAccessTokenValiditySeconds) {
      this.defaultAccessTokenValiditySeconds = defaultAccessTokenValiditySeconds;
    }

    public int getDefaultIdTokenValiditySeconds() {
      return defaultIdTokenValiditySeconds;
    }

    public void setDefaultIdTokenValiditySeconds(int defaultIdTokenValiditySeconds) {
      this.defaultIdTokenValiditySeconds = defaultIdTokenValiditySeconds;
    }

    public int getDefaultDeviceCodeValiditySeconds() {
      return defaultDeviceCodeValiditySeconds;
    }

    public void setDefaultDeviceCodeValiditySeconds(int defaultDeviceCodeValiditySeconds) {
      this.defaultDeviceCodeValiditySeconds = defaultDeviceCodeValiditySeconds;
    }

    public int getDefaultRefreshTokenValiditySeconds() {
      return defaultRefreshTokenValiditySeconds;
    }

    public void setDefaultRefreshTokenValiditySeconds(int defaultRefreshTokenValiditySeconds) {
      this.defaultRefreshTokenValiditySeconds = defaultRefreshTokenValiditySeconds;
    }

  }

  public enum ClientRegistrationAuthorizationPolicy {
    ADMINISTRATORS, REGISTERED_USERS, ANYONE
  }

  public record GrantTypes(Set<AuthorizationGrantType> forbiddenForUserClients,
      Set<AuthorizationGrantType> forbiddenForAnonymousClients) {

    public static final Set<AuthorizationGrantType> DEFAULT_FORBIDDEN_FOR_USER_CLIENTS =
        Set.copyOf(EnumSet.of(PASSWORD, TOKEN_EXCHANGE));

    public static final Set<AuthorizationGrantType> DEFAULT_FORBIDDEN_FOR_ANONYMOUS_CLIENTS =
        Set.copyOf(EnumSet.of(PASSWORD, TOKEN_EXCHANGE, CLIENT_CREDENTIALS));

    public GrantTypes {
      forbiddenForUserClients =
          Objects.isNull(forbiddenForUserClients) ? DEFAULT_FORBIDDEN_FOR_USER_CLIENTS
              : Set.copyOf(forbiddenForUserClients);
      forbiddenForAnonymousClients =
          Objects.isNull(forbiddenForAnonymousClients) ? DEFAULT_FORBIDDEN_FOR_ANONYMOUS_CLIENTS
              : Set.copyOf(forbiddenForAnonymousClients);
    }
  }

  private ClientRegistrationAuthorizationPolicy allowFor = ANYONE;

  private ClientDefaultsProperties clientDefaults = new ClientDefaultsProperties();
  private GrantTypes grantTypes = new GrantTypes(null, null);

  private boolean enable = true;

  private boolean adminOnlyCustomScopes = true;

  public ClientRegistrationAuthorizationPolicy getAllowFor() {
    return allowFor;
  }

  public void setAllowFor(ClientRegistrationAuthorizationPolicy allowFor) {
    this.allowFor = allowFor;
  }

  public ClientDefaultsProperties getClientDefaults() {
    return clientDefaults;
  }

  public void setClientDefaults(ClientDefaultsProperties clientDefaults) {
    this.clientDefaults = clientDefaults;
  }

  public GrantTypes getGrantTypes() {
    return grantTypes;
  }

  public void setGrantTypes(GrantTypes grantTypes) {
    this.grantTypes = Objects.nonNull(grantTypes) ? grantTypes : new GrantTypes(null, null);
  }

  @PostConstruct
  void warnIfGrantTypeRestrictionsAreWeakerThanDefaults() {
    warnIfMissingDefaults("client-registration.grant-types.forbidden-for-user-clients",
        grantTypes.forbiddenForUserClients(), DEFAULT_FORBIDDEN_FOR_USER_CLIENTS);
    warnIfMissingDefaults("client-registration.grant-types.forbidden-for-anonymous-clients",
        grantTypes.forbiddenForAnonymousClients(), DEFAULT_FORBIDDEN_FOR_ANONYMOUS_CLIENTS);
  }

  private static void warnIfMissingDefaults(String property, Set<AuthorizationGrantType> configured,
      Set<AuthorizationGrantType> defaults) {
    Set<AuthorizationGrantType> missing = EnumSet.noneOf(AuthorizationGrantType.class);
    missing.addAll(defaults);
    missing.removeAll(configured);
    if (!missing.isEmpty()) {
      LOG.warn("{} does not include {}, so these grant types can be requested at registration",
          property, missing);
    }
  }

  public boolean isEnable() {
    return enable;
  }

  public void setEnable(boolean enable) {
    this.enable = enable;
  }

  public boolean isAdminOnlyCustomScopes() {
    return adminOnlyCustomScopes;
  }

  public void setAdminOnlyCustomScopes(boolean enableAdminOnly) {
    this.adminOnlyCustomScopes = enableAdminOnly;
  }

}
