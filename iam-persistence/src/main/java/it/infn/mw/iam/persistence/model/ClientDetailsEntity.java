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
package it.infn.mw.iam.persistence.model;

import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.PrimaryKeyJoinColumn;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.persistence.Transient;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetails;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;

import it.infn.mw.iam.persistence.model.converter.JWKSetStringConverter;
import it.infn.mw.iam.persistence.model.converter.JWSAlgorithmStringConverter;
import it.infn.mw.iam.persistence.model.converter.PKCEAlgorithmStringConverter;
import it.infn.mw.iam.persistence.model.converter.SimpleGrantedAuthorityStringConverter;

@SuppressWarnings("deprecation")
@Entity
@Table(name = "client_details")
public class ClientDetailsEntity implements ClientDetails {

  private static final int DEFAULT_ID_TOKEN_VALIDITY_SECONDS = 600;

  private static final long serialVersionUID = -1617727085733786296L;

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "id")
  private Long id;

  /** Fields from the OAuth2 Dynamic Registration Specification */

  @Column(name = "client_id", unique = true)
  private String clientId;

  @Column(name = "client_secret")
  private String clientSecret;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "client_redirect_uri", joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "redirect_uri")
  private Set<String> redirectUris = new HashSet<>();

  @Column(name = "client_name")
  private String clientName;

  @Column(name = "client_uri")
  private String clientUri;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "client_contact", joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "contact")
  private Set<String> contacts;

  @Enumerated(EnumType.STRING)
  @Column(name = "token_endpoint_auth_method")
  private ClientAuthMethod tokenEndpointAuthMethod = ClientAuthMethod.SECRET_BASIC;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "client_scope", joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "scope")
  private Set<String> scope = new HashSet<>();

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "client_grant_type", joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "grant_type")
  private Set<String> grantTypes = new HashSet<>();

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "client_response_type", joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "response_type")
  private Set<String> responseTypes = new HashSet<>();

  @Column(name = "jwks_uri")
  private String jwksUri;

  @Column(name = "jwks")
  @Convert(converter = JWKSetStringConverter.class)
  private JWKSet jwks;

  /** Fields from OIDC Client Registration Specification **/

  @Column(name = "request_object_signing_alg")
  @Convert(converter = JWSAlgorithmStringConverter.class)
  private JWSAlgorithm requestObjectSigningAlg;

  @Column(name = "token_endpoint_auth_signing_alg")
  @Convert(converter = JWSAlgorithmStringConverter.class)
  private JWSAlgorithm tokenEndpointAuthSigningAlg;

  @Column(name = "default_max_age")
  private Integer defaultMaxAge;

  @Column(name = "require_auth_time")
  private Boolean requireAuthTime;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "client_default_acr_value", joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "default_acr_value")
  private Set<String> defaultACRvalues;

  @Column(name = "initiate_login_uri")
  private String initiateLoginUri;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "client_post_logout_redirect_uri",
      joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "post_logout_redirect_uri")
  private Set<String> postLogoutRedirectUris;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "client_request_uri", joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "request_uri")
  private Set<String> requestUris;

  /** Fields to support the ClientDetails interface **/

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "client_authority", joinColumns = @JoinColumn(name = "owner_id"))
  @Convert(converter = SimpleGrantedAuthorityStringConverter.class)
  @Column(name = "authority")
  private Set<GrantedAuthority> authorities = new HashSet<>();

  @Column(name = "access_token_validity_seconds")
  private Integer accessTokenValiditySeconds = 0;

  @Column(name = "refresh_token_validity_seconds")
  private Integer refreshTokenValiditySeconds = 0;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "client_resource", joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "resource_id")
  private Set<String> resourceIds = new HashSet<>();

  /** Our own fields **/

  @Column(name = "client_description")
  private String clientDescription = "";

  @Column(name = "reuse_refresh_tokens")
  private boolean reuseRefreshToken = true;

  @Column(name = "dynamically_registered")
  private boolean dynamicallyRegistered;

  @Column(name = "id_token_validity_seconds")
  private Integer idTokenValiditySeconds;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "created_at")
  private Date createdAt;

  @Column(name = "device_code_validity_seconds")
  private Integer deviceCodeValiditySeconds;

  @OneToOne(mappedBy = "client", cascade = CascadeType.ALL)
  @PrimaryKeyJoinColumn
  private ClientLastUsedEntity clientLastUsed;

  @OneToOne(mappedBy = "client", cascade = CascadeType.ALL)
  @PrimaryKeyJoinColumn
  private ClientRelyingPartyEntity clientRelyingParty;

  @Column(name = "active")
  private boolean active = true;

  @Column(name = "status_changed_on")
  private Date statusChangedOn;

  @Column(name = "status_changed_by")
  private String statusChangedBy;

  @Column(name = "up_scoping_enabled")
  private boolean upScopingEnabled = true;

  @Column(name = "code_challenge_method")
  @Convert(converter = PKCEAlgorithmStringConverter.class)
  private PKCEAlgorithm codeChallengeMethod;

  @PrePersist
  @PreUpdate
  private void prePersist() {
    // make sure that ID tokens always time out, default to 5 minutes
    if (getIdTokenValiditySeconds() == null) {
      setIdTokenValiditySeconds(DEFAULT_ID_TOKEN_VALIDITY_SECONDS);
    }
  }

  public ClientDetailsEntity() {
    // Empty constructor
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public String getClientDescription() {
    return clientDescription;
  }

  public void setClientDescription(String clientDescription) {
    this.clientDescription = clientDescription;
  }

  @Transient
  public boolean isAllowRefresh() {
    if (grantTypes != null) {
      return getAuthorizedGrantTypes().contains("refresh_token");
    }
    return false;
  }

  public boolean isReuseRefreshToken() {
    return reuseRefreshToken;
  }

  public void setReuseRefreshToken(boolean reuseRefreshToken) {
    this.reuseRefreshToken = reuseRefreshToken;
  }

  public Integer getIdTokenValiditySeconds() {
    return idTokenValiditySeconds;
  }

  public void setIdTokenValiditySeconds(Integer idTokenValiditySeconds) {
    this.idTokenValiditySeconds = idTokenValiditySeconds;
  }

  public boolean isDynamicallyRegistered() {
    return dynamicallyRegistered;
  }

  public void setDynamicallyRegistered(boolean dynamicallyRegistered) {
    this.dynamicallyRegistered = dynamicallyRegistered;
  }

  @Override
  @Transient
  public boolean isSecretRequired() {
    return tokenEndpointAuthMethod != null
        && (tokenEndpointAuthMethod.equals(ClientAuthMethod.SECRET_BASIC)
            || tokenEndpointAuthMethod.equals(ClientAuthMethod.SECRET_POST)
            || tokenEndpointAuthMethod.equals(ClientAuthMethod.SECRET_JWT));
  }

  @Override
  @Transient
  public boolean isScoped() {
    return getScope() != null && !getScope().isEmpty();
  }

  @Override
  public String getClientId() {
    return clientId;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  @Override
  public String getClientSecret() {
    return clientSecret;
  }

  public void setClientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
  }

  @Override
  public Set<String> getScope() {
    return scope;
  }

  public void setScope(Set<String> scope) {
    this.scope = scope;
  }

  public Set<String> getGrantTypes() {
    return grantTypes;
  }

  public void setGrantTypes(Set<String> grantTypes) {
    this.grantTypes = grantTypes;
  }

  @Override
  @Transient
  public Set<String> getAuthorizedGrantTypes() {
    return getGrantTypes();
  }

  @Override
  public Set<GrantedAuthority> getAuthorities() {
    return authorities;
  }

  public void setAuthorities(Set<GrantedAuthority> authorities) {
    this.authorities = authorities;
  }

  @Override
  public Integer getAccessTokenValiditySeconds() {
    return accessTokenValiditySeconds;
  }

  public void setAccessTokenValiditySeconds(Integer accessTokenValiditySeconds) {
    this.accessTokenValiditySeconds = accessTokenValiditySeconds;
  }

  @Override
  public Integer getRefreshTokenValiditySeconds() {
    return refreshTokenValiditySeconds;
  }

  public void setRefreshTokenValiditySeconds(Integer refreshTokenValiditySeconds) {
    this.refreshTokenValiditySeconds = refreshTokenValiditySeconds;
  }

  public Set<String> getRedirectUris() {
    return redirectUris;
  }

  public void setRedirectUris(Set<String> redirectUris) {
    this.redirectUris = redirectUris;
  }

  @Override
  @Transient
  public Set<String> getRegisteredRedirectUri() {
    return getRedirectUris();
  }

  @Override
  public Set<String> getResourceIds() {
    return resourceIds;
  }

  public void setResourceIds(Set<String> resourceIds) {
    this.resourceIds = resourceIds;
  }

  @Override
  public Map<String, Object> getAdditionalInformation() {
    return Map.of();
  }

  public String getClientName() {
    return clientName;
  }

  public void setClientName(String clientName) {
    this.clientName = clientName;
  }

  public ClientAuthMethod getTokenEndpointAuthMethod() {
    return tokenEndpointAuthMethod;
  }

  public void setTokenEndpointAuthMethod(ClientAuthMethod tokenEndpointAuthMethod) {
    this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
  }

  public Set<String> getContacts() {
    return contacts;
  }

  public void setContacts(Set<String> contacts) {
    this.contacts = contacts;
  }

  public String getClientUri() {
    return clientUri;
  }

  public void setClientUri(String clientUri) {
    this.clientUri = clientUri;
  }

  public String getJwksUri() {
    return jwksUri;
  }

  public void setJwksUri(String jwksUri) {
    this.jwksUri = jwksUri;
  }

  public JWKSet getJwks() {
    return jwks;
  }

  public void setJwks(JWKSet jwks) {
    this.jwks = jwks;
  }

  public JWSAlgorithm getRequestObjectSigningAlg() {
    return requestObjectSigningAlg;
  }

  public void setRequestObjectSigningAlg(JWSAlgorithm requestObjectSigningAlg) {
    this.requestObjectSigningAlg = requestObjectSigningAlg;
  }

  public JWSAlgorithm getTokenEndpointAuthSigningAlg() {
    return tokenEndpointAuthSigningAlg;
  }

  public void setTokenEndpointAuthSigningAlg(JWSAlgorithm tokenEndpointAuthSigningAlg) {
    this.tokenEndpointAuthSigningAlg = tokenEndpointAuthSigningAlg;
  }

  public Integer getDefaultMaxAge() {
    return defaultMaxAge;
  }

  public void setDefaultMaxAge(Integer defaultMaxAge) {
    this.defaultMaxAge = defaultMaxAge;
  }

  public Boolean getRequireAuthTime() {
    return requireAuthTime;
  }

  public void setRequireAuthTime(Boolean requireAuthTime) {
    this.requireAuthTime = requireAuthTime;
  }

  public Set<String> getResponseTypes() {
    return responseTypes;
  }

  public void setResponseTypes(Set<String> responseTypes) {
    this.responseTypes = responseTypes;
  }

  public Set<String> getDefaultACRvalues() {
    return defaultACRvalues;
  }

  public void setDefaultACRvalues(Set<String> defaultACRvalues) {
    this.defaultACRvalues = defaultACRvalues;
  }

  public String getInitiateLoginUri() {
    return initiateLoginUri;
  }

  public void setInitiateLoginUri(String initiateLoginUri) {
    this.initiateLoginUri = initiateLoginUri;
  }

  public Set<String> getPostLogoutRedirectUris() {
    return postLogoutRedirectUris;
  }

  public void setPostLogoutRedirectUris(Set<String> postLogoutRedirectUri) {
    this.postLogoutRedirectUris = postLogoutRedirectUri;
  }

  public Set<String> getRequestUris() {
    return requestUris;
  }

  public void setRequestUris(Set<String> requestUris) {
    this.requestUris = requestUris;
  }

  public Date getCreatedAt() {
    return createdAt;
  }

  public void setCreatedAt(Date createdAt) {
    this.createdAt = createdAt;
  }

  @Override
  public boolean isAutoApprove(String scope) {
    return false;
  }

  public ClientLastUsedEntity getClientLastUsed() {
    return clientLastUsed;
  }

  public void setClientLastUsed(ClientLastUsedEntity clientLastUsed) {
    this.clientLastUsed = clientLastUsed;
  }

  public ClientRelyingPartyEntity getClientRelyingParty() {
    return clientRelyingParty;
  }

  public void setClientRelyingParty(ClientRelyingPartyEntity clientRelyingParty) {
    this.clientRelyingParty = clientRelyingParty;
  }

  public boolean isActive() {
    return active;
  }

  public void setActive(boolean active) {
    this.active = active;
  }

  public boolean isUpScopingEnabled() {
    return upScopingEnabled;
  }

  public void setUpScopingEnabled(boolean upScopingEnabled) {
    this.upScopingEnabled = upScopingEnabled;
  }

  public Date getStatusChangedOn() {
    return statusChangedOn;
  }

  public void setStatusChangedOn(Date statusChangedOn) {
    this.statusChangedOn = statusChangedOn;
  }

  public String getStatusChangedBy() {
    return statusChangedBy;
  }

  public void setStatusChangedBy(String statusChangedBy) {
    this.statusChangedBy = statusChangedBy;
  }

  public PKCEAlgorithm getCodeChallengeMethod() {
    return codeChallengeMethod;
  }

  public void setCodeChallengeMethod(PKCEAlgorithm codeChallengeMethod) {
    this.codeChallengeMethod = codeChallengeMethod;
  }

  public Integer getDeviceCodeValiditySeconds() {
    return deviceCodeValiditySeconds;
  }

  public void setDeviceCodeValiditySeconds(Integer deviceCodeValiditySeconds) {
    this.deviceCodeValiditySeconds = deviceCodeValiditySeconds;
  }

  @Override
  public int hashCode() {
    return Objects.hash(clientId);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    ClientDetailsEntity other = (ClientDetailsEntity) obj;
    return Objects.equals(clientId, other.clientId);
  }

}
