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

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.persistence.CascadeType;
import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.MapKeyColumn;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import it.infn.mw.iam.persistence.model.convert.SimpleGrantedAuthorityStringConverter;

@SuppressWarnings("deprecation")
@Entity
@Table(name = "authentication_holder")
public class AuthenticationHolderEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "id")
  private Long id;

  @OneToOne(cascade = CascadeType.ALL)
  @JoinColumn(name = "user_auth_id")
  private SavedUserAuthentication userAuth;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "authentication_holder_authority",
      joinColumns = @JoinColumn(name = "owner_id"))
  @Convert(converter = SimpleGrantedAuthorityStringConverter.class)
  @Column(name = "authority")
  private Collection<GrantedAuthority> authorities;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "authentication_holder_resource_id",
      joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "resource_id")
  private Set<String> resourceIds;

  @Column(name = "approved")
  private boolean approved;

  @Column(name = "redirect_uri")
  private String redirectUri;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "authentication_holder_response_type",
      joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "response_type")
  private Set<String> responseTypes;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "authentication_holder_scope",
      joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "scope")
  private Set<String> scope;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "authentication_holder_request_parameter",
      joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "val")
  @MapKeyColumn(name = "param")
  private Map<String, String> requestParameters;

  @ManyToOne(fetch = FetchType.EAGER, optional = false)
  @JoinColumn(name = "client_id", referencedColumnName = "client_id", nullable = false)
  private ClientDetailsEntity client;

  @OneToMany(mappedBy = "owner", cascade = CascadeType.ALL, orphanRemoval = true)
  private Set<AuthenticationHolderExtension> extensions;

  @OneToMany(mappedBy = "authenticationHolder", cascade = CascadeType.ALL, orphanRemoval = true)
  private Set<OAuth2AccessTokenEntity> accessTokens = new HashSet<>();

  @OneToMany(mappedBy = "authenticationHolder", cascade = CascadeType.ALL, orphanRemoval = true)
  private Set<OAuth2RefreshTokenEntity> refreshTokens = new HashSet<>();

  @OneToMany(mappedBy = "authenticationHolder", cascade = CascadeType.ALL, orphanRemoval = true)
  private Set<AuthorizationCodeEntity> authorizationCodes = new HashSet<>();

  @OneToMany(mappedBy = "authenticationHolder", cascade = CascadeType.ALL, orphanRemoval = true)
  private Set<DeviceCode> deviceCodes = new HashSet<>();

  protected AuthenticationHolderEntity() {

  }

  public AuthenticationHolderEntity(ClientDetailsEntity client,
      OAuth2Authentication authentication) {

    this.client = client;
    this.accessTokens = new HashSet<>();
    this.refreshTokens = new HashSet<>();

    OAuth2Request o2Request = authentication.getOAuth2Request();
    if (o2Request.getAuthorities() != null) {
      this.authorities = new HashSet<>(o2Request.getAuthorities());
    }

    this.extensions = new HashSet<>();
    if (o2Request.getExtensions() != null) {
      o2Request.getExtensions().forEach((k, v) -> {
        AuthenticationHolderExtension ext = new AuthenticationHolderExtension();
        AuthenticationExtensionId id = new AuthenticationExtensionId();
        id.setKey(k);
        ext.setId(id);
        ext.setValue(v.toString());
        ext.setOwner(this);
        this.extensions.add(ext);
      });
    }
    this.redirectUri = o2Request.getRedirectUri();
    this.requestParameters = new HashMap<>();
    if (o2Request.getRequestParameters() != null) {
      this.requestParameters = retainValidParameters(o2Request.getRequestParameters());
    }
    this.resourceIds = new HashSet<>();
    if (o2Request.getResourceIds() != null) {
      this.resourceIds.addAll(o2Request.getResourceIds());
    }
    this.responseTypes = new HashSet<>();
    if (o2Request.getResponseTypes() != null) {
      this.responseTypes.addAll(o2Request.getResponseTypes());
    }
    this.scope = new HashSet<>();
    if (o2Request.getScope() != null) {
      this.scope.addAll(o2Request.getScope());
    }
    this.approved = o2Request.isApproved();

    if (authentication.getUserAuthentication() != null) {
      this.userAuth = new SavedUserAuthentication(authentication.getUserAuthentication());
    } else {
      this.userAuth = null;
    }
  }

  public Long getId() {
    return id;
  }

  @Transient
  public OAuth2Authentication getAuthentication() {
    return new OAuth2Authentication(createOAuth2Request(), getUserAuth());
  }

  private OAuth2Request createOAuth2Request() {
    return new OAuth2Request(requestParameters, client.getClientId(), authorities, approved, scope,
        resourceIds, redirectUri, responseTypes, getExtensionsMap());
  }

  public SavedUserAuthentication getUserAuth() {
    return userAuth;
  }

  public void setUserAuth(SavedUserAuthentication userAuth) {
    this.userAuth = userAuth;
  }

  public Collection<GrantedAuthority> getAuthorities() {
    return authorities;
  }

  public void setAuthorities(Collection<GrantedAuthority> authorities) {
    this.authorities = authorities;
  }

  public Set<String> getResourceIds() {
    return resourceIds;
  }

  public void setResourceIds(Set<String> resourceIds) {
    this.resourceIds = resourceIds;
  }

  public boolean isApproved() {
    return approved;
  }

  public void setApproved(boolean approved) {
    this.approved = approved;
  }

  public String getRedirectUri() {
    return redirectUri;
  }

  public void setRedirectUri(String redirectUri) {
    this.redirectUri = redirectUri;
  }

  public Set<String> getResponseTypes() {
    return responseTypes;
  }

  public void setResponseTypes(Set<String> responseTypes) {
    this.responseTypes = responseTypes;
  }

  public Set<AuthenticationHolderExtension> getExtensions() {
    return extensions;
  }

  private Map<String, Serializable> getExtensionsMap() {
    return extensions.stream()
      .filter(e -> e.getValue() instanceof Serializable)
      .collect(Collectors.toMap(AuthenticationHolderExtension::getKey,
          AuthenticationHolderExtension::getValue));
  }

  public void setExtensions(Set<AuthenticationHolderExtension> extensions) {
    this.extensions = extensions;
  }

  public Set<String> getScope() {
    return scope;
  }

  public void setScope(Set<String> scope) {
    this.scope = scope;
  }

  public Map<String, String> getRequestParameters() {
    return requestParameters;
  }

  private Map<String, String> retainValidParameters(Map<String, String> parameters) {
    return parameters.entrySet()
      .stream()
      .filter(e -> e.getValue() != null && e.getValue().length() <= 2048)
      .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
  }

  public void setRequestParameters(Map<String, String> requestParameters) {
    this.requestParameters = retainValidParameters(requestParameters);
  }

  public ClientDetailsEntity getClient() {
    return client;
  }

  public void setClient(ClientDetailsEntity client) {
    this.client = client;
  }

  public Set<OAuth2AccessTokenEntity> getAccessTokens() {
    return accessTokens;
  }

  public void addAccessToken(OAuth2AccessTokenEntity accessToken) {
    accessTokens.add(accessToken);
  }

  public Set<OAuth2RefreshTokenEntity> getRefreshTokens() {
    return refreshTokens;
  }

  public void addRefreshToken(OAuth2RefreshTokenEntity refreshToken) {
    refreshTokens.add(refreshToken);
  }

  public Set<AuthorizationCodeEntity> getAuthorizationCodes() {
    return authorizationCodes;
  }

  public void addAuthorizationCode(AuthorizationCodeEntity code) {
    authorizationCodes.add(code);
  }

  public Set<DeviceCode> getDeviceCodes() {
    return deviceCodes;
  }

  public void addDeviceCode(DeviceCode code) {
    deviceCodes.add(code);
  }
}
