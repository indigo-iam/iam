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
package it.infn.mw.iam.api.common.client;

import java.util.Date;
import java.util.Set;

import javax.validation.Valid;
import javax.validation.constraints.Email;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Null;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

import org.hibernate.validator.constraints.URL;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonView;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.google.common.collect.Sets;

import it.infn.mw.iam.api.client.management.validation.ClientIdAvailable;
import it.infn.mw.iam.api.client.management.validation.OnClientCreation;
import it.infn.mw.iam.api.client.management.validation.OnClientUpdate;
import it.infn.mw.iam.api.client.registration.validation.OnDynamicClientRegistration;
import it.infn.mw.iam.api.client.registration.validation.OnDynamicClientUpdate;
import it.infn.mw.iam.api.client.registration.validation.RedirectURI;
import it.infn.mw.iam.api.client.registration.validation.ValidGrantType;
import it.infn.mw.iam.api.client.registration.validation.ValidRedirectURIs;
import it.infn.mw.iam.api.client.registration.validation.ValidTokenEndpointAuthMethod;
import it.infn.mw.iam.api.common.ClientViews;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@ValidGrantType(groups = {OnClientCreation.class, OnClientUpdate.class,
    OnDynamicClientRegistration.class, OnDynamicClientUpdate.class})
@ValidRedirectURIs(groups = {OnClientCreation.class, OnClientUpdate.class,
    OnDynamicClientRegistration.class, OnDynamicClientUpdate.class})
@ValidTokenEndpointAuthMethod(groups = {OnClientCreation.class, OnClientUpdate.class,
    OnDynamicClientRegistration.class, OnDynamicClientUpdate.class})
@JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class,
    ClientViews.DynamicRegistration.class})
/**
 * 
 * This DTO is an annotation mess!
 * 
 * TODO: find a way to simplify annotation and validation groups
 *
 */
public class RegisteredClientDTO {
  @Null(message = "must be null in client registration requests",
      groups = OnDynamicClientRegistration.class)
  @ClientIdAvailable(groups = OnClientCreation.class)
  @JsonView({ClientViews.Limited.class, ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private String clientId;

  @Null(message = "must be null in client registration requests",
      groups = OnDynamicClientRegistration.class)
  @Size(min = 4, max = 512, groups = {OnDynamicClientUpdate.class, OnClientUpdate.class})
  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private String clientSecret;

  @Size(min = 4, max = 256,
      groups = {OnDynamicClientRegistration.class, OnClientCreation.class, OnClientUpdate.class},
      message = "Invalid length: must be between 4 and 256 characters")
  @NotBlank(groups = {OnDynamicClientRegistration.class, OnClientCreation.class},
      message = "should not be blank")
  @JsonView({ClientViews.Limited.class, ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private String clientName;

  @Size(max = 1024,
      groups = {OnDynamicClientRegistration.class, OnDynamicClientUpdate.class,
          OnClientCreation.class, OnClientUpdate.class},
      message = "Invalid ength: must be at most 1024 characters")
  @JsonView({ClientViews.Limited.class, ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private String clientDescription;

  @Valid
  @JsonView({ClientViews.Limited.class, ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private Set<@RedirectURI(message = "not a valid URL",
      groups = {OnDynamicClientRegistration.class, OnDynamicClientUpdate.class,
          OnClientCreation.class, OnClientUpdate.class}) String> redirectUris;

  @Size(max = 2048,
      groups = {OnDynamicClientRegistration.class, OnDynamicClientUpdate.class,
          OnClientCreation.class, OnClientUpdate.class})
  @URL(groups = {OnDynamicClientRegistration.class, OnDynamicClientUpdate.class,
      OnClientCreation.class, OnClientUpdate.class})
  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private String clientUri;

  @Size(max = 2048,
      groups = {OnDynamicClientRegistration.class, OnDynamicClientUpdate.class,
          OnClientCreation.class, OnClientUpdate.class})
  @URL(groups = {OnDynamicClientRegistration.class, OnDynamicClientUpdate.class,
      OnClientCreation.class, OnClientUpdate.class})
  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private String logoUri;

  @Size(max = 2048,
      groups = {OnDynamicClientRegistration.class, OnDynamicClientUpdate.class,
          OnClientCreation.class, OnClientUpdate.class})
  @URL(groups = {OnDynamicClientRegistration.class, OnDynamicClientUpdate.class,
      OnClientCreation.class, OnClientUpdate.class})
  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private String tosUri;

  @Valid
  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private Set<@Email(groups = {OnDynamicClientRegistration.class, OnDynamicClientUpdate.class,
      OnClientCreation.class, OnClientUpdate.class}) String> contacts;

  @NotEmpty(message = "Invalid client: empty grant type")
  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private Set<AuthorizationGrantType> grantTypes;

  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private Set<OAuthResponseType> responseTypes;

  @Size(max = 2048,
      groups = {OnDynamicClientRegistration.class, OnDynamicClientUpdate.class,
          OnClientCreation.class, OnClientUpdate.class})
  @URL(groups = {OnDynamicClientRegistration.class, OnDynamicClientUpdate.class,
      OnClientCreation.class, OnClientUpdate.class})
  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private String policyUri;

  @Size(max = 2048,
      groups = {OnDynamicClientRegistration.class, OnDynamicClientUpdate.class,
          OnClientCreation.class, OnClientUpdate.class})
  @URL(groups = {OnDynamicClientRegistration.class, OnDynamicClientUpdate.class,
      OnClientCreation.class, OnClientUpdate.class})
  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private String jwksUri;

  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private TokenEndpointAuthenticationMethod tokenEndpointAuthMethod;

  @Valid
  @Size(max = 512,
      groups = {OnDynamicClientRegistration.class, OnDynamicClientUpdate.class,
          OnClientCreation.class, OnClientUpdate.class})
  @JsonSerialize(using = CollectionAsStringSerializer.class)
  @JsonDeserialize(using = StringAsSetOfStringsDeserializer.class)
  @JsonView({ClientViews.Limited.class, ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private Set<@NotBlank(groups = {OnDynamicClientRegistration.class, OnDynamicClientUpdate.class,
      OnClientCreation.class, OnClientUpdate.class},
      message = "must not include blank strings") @Size(min = 1, max = 2048,
          message = "string size must be between 1 and 2048",
          groups = {OnDynamicClientRegistration.class, OnDynamicClientUpdate.class,
              OnClientCreation.class, OnClientUpdate.class}) String> scope =
          Sets.newHashSet();

  @Min(value = 0, groups = OnClientCreation.class)
  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class})
  private Integer accessTokenValiditySeconds;

  @Min(value = 0, groups = OnClientCreation.class)
  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class})
  private Integer refreshTokenValiditySeconds;

  @Min(value = 0, groups = OnClientCreation.class)
  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class})
  private Integer idTokenValiditySeconds;

  @Min(value = 0, groups = OnClientCreation.class)
  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class})
  private Integer deviceCodeValiditySeconds;

  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private Integer defaultMaxAge;

  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private boolean reuseRefreshToken;

  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private boolean dynamicallyRegistered;

  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class})
  private boolean allowIntrospection;

  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private boolean clearAccessTokensOnRefresh;

  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private boolean requireAuthTime;

  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private String registrationAccessToken;

  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private String registrationClientUri;

  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private Date clientSecretExpiresAt;

  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private Date clientIdIssuedAt;

  @JsonView({ClientViews.Limited.class, ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  private Date createdAt;

  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  @Size(max = 2048, groups = {OnClientCreation.class, OnClientUpdate.class})
  private String jwk;

  @JsonView({ClientViews.Full.class, ClientViews.ClientManagement.class,
      ClientViews.DynamicRegistration.class})
  @Pattern(regexp = "^$|none|plain|S256",
      message = "must be either an empty string, none, plain or S256",
      groups = {OnClientCreation.class,
      OnClientUpdate.class, OnDynamicClientRegistration.class, OnDynamicClientUpdate.class})
  private String codeChallengeMethod;

  public String getClientId() {
    return clientId;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  public String getClientSecret() {
    return clientSecret;
  }

  public void setClientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
  }

  public String getClientName() {
    return clientName;
  }

  public void setClientName(String clientName) {
    this.clientName = clientName;
  }

  public String getClientDescription() {
    return clientDescription;
  }

  public void setClientDescription(String clientDescription) {
    this.clientDescription = clientDescription;
  }

  public Set<String> getRedirectUris() {
    return redirectUris;
  }

  public void setRedirectUris(Set<String> redirectUris) {
    this.redirectUris = redirectUris;
  }

  public String getClientUri() {
    return clientUri;
  }

  public void setClientUri(String clientUri) {
    this.clientUri = clientUri;
  }

  public String getLogoUri() {
    return logoUri;
  }

  public void setLogoUri(String logoUri) {
    this.logoUri = logoUri;
  }

  public String getTosUri() {
    return tosUri;
  }

  public void setTosUri(String tosUri) {
    this.tosUri = tosUri;
  }

  public Set<String> getContacts() {
    return contacts;
  }

  public void setContacts(Set<String> contacts) {
    this.contacts = contacts;
  }

  public Set<AuthorizationGrantType> getGrantTypes() {
    return grantTypes;
  }

  public void setGrantTypes(Set<AuthorizationGrantType> grantTypes) {
    this.grantTypes = grantTypes;
  }

  public Set<OAuthResponseType> getResponseTypes() {
    return responseTypes;
  }

  public void setResponseTypes(Set<OAuthResponseType> responseTypes) {
    this.responseTypes = responseTypes;
  }

  public String getPolicyUri() {
    return policyUri;
  }

  public void setPolicyUri(String policyUri) {
    this.policyUri = policyUri;
  }

  public String getJwksUri() {
    return jwksUri;
  }

  public void setJwksUri(String jwksUri) {
    this.jwksUri = jwksUri;
  }

  public TokenEndpointAuthenticationMethod getTokenEndpointAuthMethod() {
    return tokenEndpointAuthMethod;
  }

  public void setTokenEndpointAuthMethod(
      TokenEndpointAuthenticationMethod tokenEndpointAuthMethod) {
    this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
  }

  public Set<String> getScope() {
    return scope;
  }

  public void setScope(Set<String> scope) {
    this.scope = scope;
  }

  public Integer getAccessTokenValiditySeconds() {
    return accessTokenValiditySeconds;
  }

  public void setAccessTokenValiditySeconds(Integer accessTokenValiditySeconds) {
    this.accessTokenValiditySeconds = accessTokenValiditySeconds;
  }

  public Integer getRefreshTokenValiditySeconds() {
    return refreshTokenValiditySeconds;
  }

  public void setRefreshTokenValiditySeconds(Integer refreshTokenValiditySeconds) {
    this.refreshTokenValiditySeconds = refreshTokenValiditySeconds;
  }

  public Integer getIdTokenValiditySeconds() {
    return idTokenValiditySeconds;
  }

  public void setIdTokenValiditySeconds(Integer idTokenValiditySeconds) {
    this.idTokenValiditySeconds = idTokenValiditySeconds;
  }

  public Integer getDeviceCodeValiditySeconds() {
    return deviceCodeValiditySeconds;
  }

  public void setDeviceCodeValiditySeconds(Integer deviceCodeValiditySeconds) {
    this.deviceCodeValiditySeconds = deviceCodeValiditySeconds;
  }

  public boolean isReuseRefreshToken() {
    return reuseRefreshToken;
  }

  public void setReuseRefreshToken(boolean reuseRefreshToken) {
    this.reuseRefreshToken = reuseRefreshToken;
  }

  public boolean isDynamicallyRegistered() {
    return dynamicallyRegistered;
  }

  public void setDynamicallyRegistered(boolean dynamicallyRegistered) {
    this.dynamicallyRegistered = dynamicallyRegistered;
  }

  public boolean isAllowIntrospection() {
    return allowIntrospection;
  }

  public void setAllowIntrospection(boolean allowIntrospection) {
    this.allowIntrospection = allowIntrospection;
  }

  public boolean isClearAccessTokensOnRefresh() {
    return clearAccessTokensOnRefresh;
  }

  public void setClearAccessTokensOnRefresh(boolean clearAccessTokensOnRefresh) {
    this.clearAccessTokensOnRefresh = clearAccessTokensOnRefresh;
  }

  public boolean isRequireAuthTime() {
    return requireAuthTime;
  }

  public void setRequireAuthTime(boolean requireAuthTime) {
    this.requireAuthTime = requireAuthTime;
  }

  public String getRegistrationAccessToken() {
    return registrationAccessToken;
  }

  public void setRegistrationAccessToken(String registrationAccessToken) {
    this.registrationAccessToken = registrationAccessToken;
  }

  public String getRegistrationClientUri() {
    return registrationClientUri;
  }

  public void setRegistrationClientUri(String registrationClientUri) {
    this.registrationClientUri = registrationClientUri;
  }

  public Date getClientSecretExpiresAt() {
    return clientSecretExpiresAt;
  }

  public void setClientSecretExpiresAt(Date clientSecretExpiresAt) {
    this.clientSecretExpiresAt = clientSecretExpiresAt;
  }

  public Date getClientIdIssuedAt() {
    return clientIdIssuedAt;
  }

  public void setClientIdIssuedAt(Date clientIdIssuedAt) {
    this.clientIdIssuedAt = clientIdIssuedAt;
  }

  public Date getCreatedAt() {
    return createdAt;
  }

  public void setCreatedAt(Date createdAt) {
    this.createdAt = createdAt;
  }

  public String getJwk() {
    return jwk;
  }

  public void setJwk(String jwk) {
    this.jwk = jwk;
  }

  public String getCodeChallengeMethod() {
    return codeChallengeMethod;
  }

  public void setCodeChallengeMethod(String codeChallengeMethod) {
    this.codeChallengeMethod = codeChallengeMethod;
  }

  public Integer getDefaultMaxAge() {
    return defaultMaxAge;
  }

  public void setDefaultMaxAge(Integer defaultMaxAge) {
    this.defaultMaxAge = defaultMaxAge;
  }

}
