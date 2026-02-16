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
import java.util.HashMap;
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
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.PrimaryKeyJoinColumn;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.persistence.Transient;
import javax.persistence.UniqueConstraint;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetails;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWT;

import it.infn.mw.iam.persistence.model.convert.JWEAlgorithmStringConverter;
import it.infn.mw.iam.persistence.model.convert.JWEEncryptionMethodStringConverter;
import it.infn.mw.iam.persistence.model.convert.JWKSetStringConverter;
import it.infn.mw.iam.persistence.model.convert.JWSAlgorithmStringConverter;
import it.infn.mw.iam.persistence.model.convert.JWTStringConverter;
import it.infn.mw.iam.persistence.model.convert.PKCEAlgorithmStringConverter;
import it.infn.mw.iam.persistence.model.convert.SimpleGrantedAuthorityStringConverter;

@SuppressWarnings("deprecation")
@Entity
@Table(name = "client_details", uniqueConstraints = @UniqueConstraint(columnNames = "client_id"))
public class ClientDetailsEntity implements ClientDetails {

  private static final long serialVersionUID = -1617727085733786296L;

  private static final int DEFAULT_ID_TOKEN_VALIDITY_SECONDS = 600;

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "id")
  private Long id;

  /*
   * Fields from the OAuth2 Dynamic Registration Specification
   */
  @Column(name = "client_id")
  private String clientId;

  @Column(name = "client_secret")
  private String clientSecret;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "client_redirect_uri", joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "redirect_uri")
  private Set<String> redirectUris;

  @Column(name = "client_name")
  private String clientName;

  @Column(name = "client_uri")
  private String clientUri;

  @Column(name = "logo_uri")
  private String logoUri;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "client_contact", joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "contact")
  private Set<String> contacts;

  @Column(name = "tos_uri")
  private String tosUri;

  @Enumerated(EnumType.STRING)
  @Column(name = "token_endpoint_auth_method")
  private AuthMethod tokenEndpointAuthMethod;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "client_scope", joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "scope")
  private Set<String> scope;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "client_grant_type", joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "grant_type")
  private Set<String> grantTypes;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "client_response_type", joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "response_type")
  private Set<String> responseTypes;

  @Column(name = "policy_uri")
  private String policyUri;

  @Column(name = "jwks_uri")
  private String jwksUri;

  @Column(name = "jwks")
  @Convert(converter = JWKSetStringConverter.class)
  private JWKSet jwks;

  @Column(name = "software_id")
  private String softwareId;

  @Column(name = "software_version")
  private String softwareVersion;

  /*
   * Fields from OIDC Client Registration Specification
   */
  @Enumerated(EnumType.STRING)
  @Column(name = "application_type")
  private AppType applicationType;

  @Column(name = "sector_identifier_uri")
  private String sectorIdentifierUri;

  @Enumerated(EnumType.STRING)
  @Column(name = "subject_type")
  private SubjectType subjectType;

  @Column(name = "request_object_signing_alg")
  @Convert(converter = JWSAlgorithmStringConverter.class)
  private JWSAlgorithm requestObjectSigningAlg;

  @Column(name = "user_info_signed_response_alg")
  @Convert(converter = JWSAlgorithmStringConverter.class)
  private JWSAlgorithm userInfoSignedResponseAlg;

  @Column(name = "user_info_encrypted_response_alg")
  @Convert(converter = JWEAlgorithmStringConverter.class)
  private JWEAlgorithm userInfoEncryptedResponseAlg;

  @Column(name = "user_info_encrypted_response_enc")
  @Convert(converter = JWEEncryptionMethodStringConverter.class)
  private EncryptionMethod userInfoEncryptedResponseEnc;

  @Column(name = "id_token_signed_response_alg")
  @Convert(converter = JWSAlgorithmStringConverter.class)
  private JWSAlgorithm idTokenSignedResponseAlg;

  @Column(name = "id_token_encrypted_response_alg")
  @Convert(converter = JWEAlgorithmStringConverter.class)
  private JWEAlgorithm idTokenEncryptedResponseAlg;

  @Column(name = "id_token_encrypted_response_enc")
  @Convert(converter = JWEEncryptionMethodStringConverter.class)
  private EncryptionMethod idTokenEncryptedResponseEnc;

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

  /*
   * Fields to support the ClientDetails interface
   */
  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "client_authority", joinColumns = @JoinColumn(name = "owner_id"))
  @Convert(converter = SimpleGrantedAuthorityStringConverter.class)
  @Column(name = "authority")
  private Set<GrantedAuthority> authorities;

  @Column(name = "access_token_validity_seconds")
  private Integer accessTokenValiditySeconds;

  @Column(name = "refresh_token_validity_seconds")
  private Integer refreshTokenValiditySeconds;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "client_resource", joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "resource_id")
  private Set<String> resourceIds;

  @Transient
  private Map<String, Object> additionalInformation;

  /*
   * Internal fields
   */
  @Column(name = "client_description")
  private String clientDescription;

  @Column(name = "reuse_refresh_tokens")
  private boolean reuseRefreshToken;

  @Column(name = "dynamically_registered")
  private boolean dynamicallyRegistered;

  @Column(name = "allow_introspection")
  private boolean allowIntrospection;

  @Column(name = "id_token_validity_seconds")
  private Integer idTokenValiditySeconds;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "created_at")
  private Date createdAt;

  @Column(name = "clear_access_tokens_on_refresh")
  private boolean clearAccessTokensOnRefresh;

  @Column(name = "device_code_validity_seconds")
  private Integer deviceCodeValiditySeconds;

  @OneToOne(mappedBy = "client", cascade = CascadeType.ALL)
  @PrimaryKeyJoinColumn
  private ClientLastUsedEntity clientLastUsed;

  @OneToOne(mappedBy = "client", cascade = CascadeType.ALL)
  @PrimaryKeyJoinColumn
  private ClientRelyingPartyEntity clientRelyingParty;

  @Column(name = "active")
  private boolean active;

  @Column(name = "status_changed_on")
  private Date statusChangedOn;

  @Column(name = "status_changed_by")
  private String statusChangedBy;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "client_claims_redirect_uri",
      joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "redirect_uri")
  private Set<String> claimsRedirectUris;

  @Column(name = "software_statement")
  @Convert(converter = JWTStringConverter.class)
  private JWT softwareStatement;

  @Column(name = "code_challenge_method")
  @Convert(converter = PKCEAlgorithmStringConverter.class)
  private PKCEAlgorithm codeChallengeMethod;

  @OneToMany(mappedBy = "client", cascade = CascadeType.ALL, orphanRemoval = true)
  private Set<AuthenticationHolderEntity> authenticationHolders;

  @OneToMany(mappedBy = "client", cascade = CascadeType.ALL, orphanRemoval = true)
  private Set<OAuth2AccessTokenEntity> accessTokens;

  @OneToMany(mappedBy = "client", cascade = CascadeType.ALL, orphanRemoval = true)
  private Set<OAuth2RefreshTokenEntity> refreshTokens;

  @OneToMany(mappedBy = "client", cascade = CascadeType.ALL, orphanRemoval = true)
  private Set<DeviceCode> deviceCodes;

  @Column(name = "up_scoping_enabled")
  private boolean upScopingEnabled;

  public ClientDetailsEntity() {

    accessTokens = new HashSet<>();
    accessTokenValiditySeconds = 0;
    active = true;
    additionalInformation = new HashMap<>();
    allowIntrospection = true;
    authenticationHolders = new HashSet<>();
    authorities = new HashSet<>();
    clearAccessTokensOnRefresh = false;
    clientDescription = "";
    deviceCodes = new HashSet<>();
    dynamicallyRegistered = false;
    grantTypes = new HashSet<>();
    redirectUris = new HashSet<>();
    refreshTokenValiditySeconds = 0;
    refreshTokens = new HashSet<>();
    resourceIds = new HashSet<>();
    responseTypes = new HashSet<>();
    reuseRefreshToken = true;
    scope = new HashSet<>();
    tokenEndpointAuthMethod = AuthMethod.SECRET_BASIC;
    upScopingEnabled = true;
  }

  @PrePersist
  @PreUpdate
  private void prePersist() {
    // make sure that ID tokens always time out, default to 5 minutes
    if (getIdTokenValiditySeconds() == null) {
      setIdTokenValiditySeconds(DEFAULT_ID_TOKEN_VALIDITY_SECONDS);
    }
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
    if (grantTypes != null && !grantTypes.isEmpty()) {
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

  public boolean isAllowIntrospection() {
    return allowIntrospection;
  }

  public void setAllowIntrospection(boolean allowIntrospection) {
    this.allowIntrospection = allowIntrospection;
  }

  @Override
  @Transient
  public boolean isSecretRequired() {
    if (tokenEndpointAuthMethod == null) {
      return false;
    }
    return AuthMethod.SECRET_BASIC.equals(tokenEndpointAuthMethod)
        || AuthMethod.SECRET_POST.equals(tokenEndpointAuthMethod)
        || AuthMethod.SECRET_JWT.equals(tokenEndpointAuthMethod);
  }

  @Override
  @Transient
  public boolean isScoped() {
    return scope != null && !scope.isEmpty();
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
    return grantTypes;
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
    return redirectUris;
  }

  @Override
  public Set<String> getResourceIds() {
    return resourceIds;
  }

  public void setResourceIds(Set<String> resourceIds) {
    this.resourceIds = resourceIds;
  }

  @Override
  @Transient
  public Map<String, Object> getAdditionalInformation() {
    return this.additionalInformation;
  }

  public AppType getApplicationType() {
    return applicationType;
  }

  public void setApplicationType(AppType applicationType) {
    this.applicationType = applicationType;
  }

  public String getClientName() {
    return clientName;
  }

  public void setClientName(String clientName) {
    this.clientName = clientName;
  }

  public AuthMethod getTokenEndpointAuthMethod() {
    return tokenEndpointAuthMethod;
  }

  public void setTokenEndpointAuthMethod(AuthMethod tokenEndpointAuthMethod) {
    this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
  }

  public SubjectType getSubjectType() {
    return subjectType;
  }

  public void setSubjectType(SubjectType subjectType) {
    this.subjectType = subjectType;
  }

  public Set<String> getContacts() {
    return contacts;
  }

  public void setContacts(Set<String> contacts) {
    this.contacts = contacts;
  }

  public String getLogoUri() {
    return logoUri;
  }

  public void setLogoUri(String logoUri) {
    this.logoUri = logoUri;
  }

  public String getPolicyUri() {
    return policyUri;
  }

  public void setPolicyUri(String policyUri) {
    this.policyUri = policyUri;
  }

  public String getClientUri() {
    return clientUri;
  }

  public void setClientUri(String clientUri) {
    this.clientUri = clientUri;
  }

  public String getTosUri() {
    return tosUri;
  }

  public void setTosUri(String tosUri) {
    this.tosUri = tosUri;
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

  public String getSectorIdentifierUri() {
    return sectorIdentifierUri;
  }

  public void setSectorIdentifierUri(String sectorIdentifierUri) {
    this.sectorIdentifierUri = sectorIdentifierUri;
  }

  public JWSAlgorithm getRequestObjectSigningAlg() {
    return requestObjectSigningAlg;
  }

  public void setRequestObjectSigningAlg(JWSAlgorithm requestObjectSigningAlg) {
    this.requestObjectSigningAlg = requestObjectSigningAlg;
  }

  public JWSAlgorithm getUserInfoSignedResponseAlg() {
    return userInfoSignedResponseAlg;
  }

  public void setUserInfoSignedResponseAlg(JWSAlgorithm userInfoSignedResponseAlg) {
    this.userInfoSignedResponseAlg = userInfoSignedResponseAlg;
  }

  public JWEAlgorithm getUserInfoEncryptedResponseAlg() {
    return userInfoEncryptedResponseAlg;
  }

  public void setUserInfoEncryptedResponseAlg(JWEAlgorithm userInfoEncryptedResponseAlg) {
    this.userInfoEncryptedResponseAlg = userInfoEncryptedResponseAlg;
  }

  public EncryptionMethod getUserInfoEncryptedResponseEnc() {
    return userInfoEncryptedResponseEnc;
  }

  public void setUserInfoEncryptedResponseEnc(EncryptionMethod userInfoEncryptedResponseEnc) {
    this.userInfoEncryptedResponseEnc = userInfoEncryptedResponseEnc;
  }

  public JWSAlgorithm getIdTokenSignedResponseAlg() {
    return idTokenSignedResponseAlg;
  }

  public void setIdTokenSignedResponseAlg(JWSAlgorithm idTokenSignedResponseAlg) {
    this.idTokenSignedResponseAlg = idTokenSignedResponseAlg;
  }

  public JWEAlgorithm getIdTokenEncryptedResponseAlg() {
    return idTokenEncryptedResponseAlg;
  }

  public void setIdTokenEncryptedResponseAlg(JWEAlgorithm idTokenEncryptedResponseAlg) {
    this.idTokenEncryptedResponseAlg = idTokenEncryptedResponseAlg;
  }

  public EncryptionMethod getIdTokenEncryptedResponseEnc() {
    return idTokenEncryptedResponseEnc;
  }

  public void setIdTokenEncryptedResponseEnc(EncryptionMethod idTokenEncryptedResponseEnc) {
    this.idTokenEncryptedResponseEnc = idTokenEncryptedResponseEnc;
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

  public boolean isClearAccessTokensOnRefresh() {
    return clearAccessTokensOnRefresh;
  }

  public void setClearAccessTokensOnRefresh(boolean clearAccessTokensOnRefresh) {
    this.clearAccessTokensOnRefresh = clearAccessTokensOnRefresh;
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

  public Set<String> getClaimsRedirectUris() {
    return claimsRedirectUris;
  }

  public void setClaimsRedirectUris(Set<String> claimsRedirectUris) {
    this.claimsRedirectUris = claimsRedirectUris;
  }

  public JWT getSoftwareStatement() {
    return softwareStatement;
  }

  public void setSoftwareStatement(JWT softwareStatement) {
    this.softwareStatement = softwareStatement;
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

  public String getSoftwareId() {
    return softwareId;
  }

  public void setSoftwareId(String softwareId) {
    this.softwareId = softwareId;
  }

  public String getSoftwareVersion() {
    return softwareVersion;
  }

  public void setSoftwareVersion(String softwareVersion) {
    this.softwareVersion = softwareVersion;
  }

  public Set<AuthenticationHolderEntity> getAuthenticationHolders() {
    return authenticationHolders;
  }

  public Set<OAuth2AccessTokenEntity> getAccessTokens() {
    return accessTokens;
  }

  public Set<OAuth2RefreshTokenEntity> getRefreshTokens() {
    return refreshTokens;
  }

  public Set<DeviceCode> getDeviceCodes() {
    return deviceCodes;
  }

  public boolean isUpScopingEnabled() {
    return upScopingEnabled;
  }

  public void setUpScopingEnabled(boolean upScopingEnabled) {
    this.upScopingEnabled = upScopingEnabled;
  }

  @Override
  public int hashCode() {
    return Objects.hash(clientId, id);
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
    return Objects.equals(clientId, other.clientId) && Objects.equals(id, other.id);
  }

}
