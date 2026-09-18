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

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.persistence.Transient;

import org.springframework.security.oauth2.common.OAuth2AccessToken;

import com.nimbusds.jwt.JWT;

@SuppressWarnings("deprecation")
@Entity
@Table(name = "access_token")
public class OAuth2AccessTokenEntity implements OAuth2AccessToken {

  public static final String ID_TOKEN_FIELD_NAME = "id_token";

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "id")
  private Long id;

  @ManyToOne
  @JoinColumn(name = "client_id")
  private ClientDetailsEntity client;

  @ManyToOne
  @JoinColumn(name = "auth_holder_id")
  private AuthenticationHolderEntity authenticationHolder;

  @Transient
  private JWT jwtValue;

  @Column(name = "token_value_hash", length = 64)
  private String tokenValueHash;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "expiration")
  private Date expiration;

  @Column(name = "token_type")
  private String tokenType = OAuth2AccessToken.BEARER_TYPE;

  @ManyToOne
  @JoinColumn(name = "refresh_token_id")
  private OAuth2RefreshTokenEntity refreshToken;

  @Column(name = "scope")
  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(joinColumns = @JoinColumn(name = "owner_id"), name = "token_scope")
  private Set<String> scopes;

  @Transient
  private Map<String, Object> additionalInformation = new HashMap<>();

  public OAuth2AccessTokenEntity() {
    // Empty constructor
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  @Override
  @Transient
  public Map<String, Object> getAdditionalInformation() {
    return additionalInformation;
  }

  public AuthenticationHolderEntity getAuthenticationHolder() {
    return authenticationHolder;
  }

  public void setAuthenticationHolder(AuthenticationHolderEntity authenticationHolder) {
    this.authenticationHolder = authenticationHolder;
  }

  public ClientDetailsEntity getClient() {
    return client;
  }

  public void setClient(ClientDetailsEntity client) {
    this.client = client;
  }

  @Override
  @Transient
  public String getValue() {
    return jwtValue.serialize();
  }

  @Override
  public Date getExpiration() {
    return expiration;
  }

  public void setExpiration(Date expiration) {
    this.expiration = expiration;
  }

  @Override
  public String getTokenType() {
    return tokenType;
  }

  public void setTokenType(String tokenType) {
    this.tokenType = tokenType;
  }

  @Override
  public OAuth2RefreshTokenEntity getRefreshToken() {
    return refreshToken;
  }

  public void setRefreshToken(OAuth2RefreshTokenEntity refreshToken) {
    this.refreshToken = refreshToken;
  }

  @Override
  public Set<String> getScope() {
    return scopes;
  }

  public void setScope(Set<String> scope) {
    this.scopes = scope;
  }

  @Override
  @Transient
  public boolean isExpired() {
    return expiration != null && expiration.toInstant().isBefore(Instant.now());
  }

  @Transient
  public JWT getJwt() {
    return jwtValue;
  }

  public void setJwt(JWT jwt) {
    this.jwtValue = jwt;
  }

  public String getTokenValueHash() {
    return tokenValueHash;
  }

  public void setTokenValueHash(String hash) {
    this.tokenValueHash = hash;
  }

  @Override
  @Transient
  public int getExpiresIn() {

    if (expiration == null) {
      return -1;
    }
    long seconds = Duration.between(Instant.now(), expiration.toInstant()).getSeconds();
    return (int) Math.max(0, seconds);
  }

  @Transient
  public void setIdToken(JWT idToken) {
    if (idToken != null) {
      additionalInformation.put(ID_TOKEN_FIELD_NAME, idToken.serialize());
    }
  }

  @Transient
  public Set<String> getAudiences() {
    try {
      return jwtValue.getJWTClaimsSet().getAudience().stream().collect(Collectors.toSet());
    } catch (ParseException e) {
      return Set.of();
    }
  }
}

