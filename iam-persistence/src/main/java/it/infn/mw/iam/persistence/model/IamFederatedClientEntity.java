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
import java.util.Date;
import java.util.Set;

import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.nimbusds.jose.jwk.JWKSet;

@Entity
@Table(name = "iam_federated_client")
public class IamFederatedClientEntity implements Serializable {

  private static final long serialVersionUID = 1L;

  @Id
  @Column(name = "id")
  @JsonIgnore
  private Long id;

  @Column(name = "client_id", nullable = false)
  private String clientId;

  @Column(name = "client_secret")
  @JsonIgnore
  private String clientSecret;

  @Column(name = "client_name", nullable = false)
  private String clientName;

  @Column(name = "token_endpoint_auth_method")
  private String tokenEndpointAuthMethod;

  @Column(name = "jwks_uri")
  private String jwksUri;

  @Column(name = "jwks")
  @Convert(converter = IamJWKSetStringConverter.class)
  private JWKSet jwks;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "created_at")
  private Date createdAt;

  @Column(name = "active")
  private boolean active;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "iam_federated_client_redirect_uri",
      joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "redirect_uri")
  private Set<String> redirectUris;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "iam_federated_client_grant_type",
      joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "grant_type")
  private Set<String> grantTypes;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "iam_federated_client_response_type",
      joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "response_type")
  private Set<String> responseTypes;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "iam_federated_client_scope",
      joinColumns = @JoinColumn(name = "owner_id"))
  @Column(name = "scope")
  private Set<String> scope;

  @Column(name = "expiration", nullable = false)
  private Date expiration;

  @Column(name = "entity_id", nullable = false)
  private String entityId;

  public IamFederatedClientEntity() {
    // empty constructor
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

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

  public String getTokenEndpointAuthMethod() {
    return tokenEndpointAuthMethod;
  }

  public void setTokenEndpointAuthMethod(String tokenEndpointAuthMethod) {
    this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
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

  public Date getCreatedAt() {
    return createdAt;
  }

  public void setCreatedAt(Date createdAt) {
    this.createdAt = createdAt;
  }

  public boolean isActive() {
    return active;
  }

  public void setActive(boolean active) {
    this.active = active;
  }

  public Set<String> getRedirectUris() {
    return redirectUris;
  }

  public void setRedirectUris(Set<String> redirectUris) {
    this.redirectUris = redirectUris;
  }

  public Set<String> getGrantTypes() {
    return grantTypes;
  }

  public void setGrantTypes(Set<String> grantTypes) {
    this.grantTypes = grantTypes;
  }

  public Set<String> getResponseTypes() {
    return responseTypes;
  }

  public void setResponseTypes(Set<String> responseTypes) {
    this.responseTypes = responseTypes;
  }

  public Set<String> getScope() {
    return scope;
  }

  public void setScope(Set<String> scope) {
    this.scope = scope;
  }

  public Date getExpiration() {
    return expiration;
  }

  public void setExpiration(Date expiration) {
    this.expiration = expiration;
  }

  public String getEntityId() {
    return entityId;
  }

  public void setEntityId(String entityId) {
    this.entityId = entityId;
  }
}
