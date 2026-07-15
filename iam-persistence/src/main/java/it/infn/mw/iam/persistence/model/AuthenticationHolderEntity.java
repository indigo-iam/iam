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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

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
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import it.infn.mw.iam.persistence.model.converter.SimpleGrantedAuthorityStringConverter;

@SuppressWarnings("deprecation")
@Entity
@Table(name = "authentication_holder")
public class AuthenticationHolderEntity implements Serializable {

  private static final Logger logger = LoggerFactory.getLogger(AuthenticationHolderEntity.class);
  private static final long serialVersionUID = 1L;

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
  private Set<GrantedAuthority> authorities;

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
  @CollectionTable(name = "authentication_holder_extension",
      joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "val", length = 2048)
  @MapKeyColumn(name = "extension", length = 2048)
  private Map<String, String> extensions;

  @ManyToOne
  @JoinColumn(
      name = "client_id",
      referencedColumnName = "client_id")
  private ClientDetailsEntity client;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "authentication_holder_scope",
      joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "scope")
  private Set<String> scopes;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "authentication_holder_request_parameter",
      joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "val")
  @MapKeyColumn(name = "param")
  private Map<String, String> requestParameters;

  public AuthenticationHolderEntity() {
    // Empty constructor
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  @Transient
  public OAuth2Authentication getAuthentication() {
    return new OAuth2Authentication(createOAuth2Request(), getUserAuth());
  }

  private OAuth2Request createOAuth2Request() {

    Map<String, Serializable> serializableExtensions = null;

    if (extensions != null) {
      serializableExtensions = new HashMap<>();
      extensions.forEach(serializableExtensions::put);
    }

    return new OAuth2Request(requestParameters, client.getClientId(), authorities, approved, scopes, resourceIds,
        redirectUri, responseTypes, serializableExtensions);
  }

  public void setAuthentication(OAuth2Authentication authentication) {

    OAuth2Request o2Request = authentication.getOAuth2Request();
    setAuthorities(
        o2Request.getAuthorities() == null ? null : new HashSet<>(o2Request.getAuthorities()));
    if (o2Request.getExtensions() == null) {
      setExtensions(null);
    } else {
      Map<String, String> stringExtensions = new HashMap<>();
      o2Request.getExtensions().forEach((key, value) -> {
        if (value != null) {
          stringExtensions.put(key, value.toString());
        }
      });
      setExtensions(stringExtensions);
    }
    setRedirectUri(o2Request.getRedirectUri());
    setRequestParameters(o2Request.getRequestParameters() == null ? null
        : new HashMap<>(o2Request.getRequestParameters()));
    setResourceIds(
        o2Request.getResourceIds() == null ? null : new HashSet<>(o2Request.getResourceIds()));
    setResponseTypes(
        o2Request.getResponseTypes() == null ? null : new HashSet<>(o2Request.getResponseTypes()));
    setScope(o2Request.getScope() == null ? null : new HashSet<>(o2Request.getScope()));
    setApproved(o2Request.isApproved());
  }

  public SavedUserAuthentication getUserAuth() {
    return userAuth;
  }

  public void setUserAuth(SavedUserAuthentication userAuth) {
    this.userAuth = userAuth;
  }

  public Set<GrantedAuthority> getAuthorities() {
    return authorities;
  }

  public void setAuthorities(Set<GrantedAuthority> authorities) {
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

  public Map<String, String> getExtensions() {
    return extensions;
  }

  public void setExtensions(Map<String, String> extensions) {
    this.extensions = extensions;
  }

  public ClientDetailsEntity getClient() {
    return client;
  }

  public void setClient(ClientDetailsEntity client) {
    this.client = client;
  }

  public Set<String> getScope() {
    return scopes;
  }

  public void setScope(Set<String> scopes) {
    this.scopes = scopes;
  }

  public Map<String, String> getRequestParameters() {
    return requestParameters;
  }

  public void setRequestParameters(Map<String, String> requestParameters) {
    this.requestParameters = new HashMap<>();
    if (requestParameters == null) {
      return;
    }
    requestParameters.forEach((k, v) -> {
      if (v == null) {
        logger.warn("The request parameter {} has a null value.", k);
      } else if (v.length() > 2048) {
        logger.warn(
            "The length of the request parameter {} exceeds 2048 characters, with the value: {}...",
            k, v.substring(0, 20));
      } else {
        this.requestParameters.put(k, v);
      }
    });
  }
}
