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
import java.util.Date;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.persistence.Transient;

import org.springframework.security.oauth2.common.OAuth2RefreshToken;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

@SuppressWarnings("deprecation")
@Entity
@Table(name = "refresh_token")
public class OAuth2RefreshTokenEntity implements OAuth2RefreshToken {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "id")
  private Long id;

  @Column(name = "token_value", length = 4096)
  private String tokenValue;

  @Temporal(TemporalType.TIMESTAMP)
  @Column(name = "expiration")
  private Date expiration;

  @ManyToOne(fetch = FetchType.EAGER, optional = false)
  @JoinColumn(name = "auth_holder_id", nullable = false)
  private AuthenticationHolderEntity authenticationHolder;

  @ManyToOne(fetch = FetchType.EAGER)
  @JoinColumn(name = "client_id")
  private ClientDetailsEntity client;

  @OneToMany(mappedBy = "refreshToken", cascade = CascadeType.ALL, orphanRemoval = true)
  private Set<OAuth2AccessTokenEntity> accessTokens = new HashSet<>();

  @Transient
  private JWT jwt;

  protected OAuth2RefreshTokenEntity() {
  }

  protected OAuth2RefreshTokenEntity(ClientDetailsEntity client,
      AuthenticationHolderEntity authenticationHolder, OAuth2AccessTokenEntity accessToken) {

    Objects.nonNull(client);
    Objects.nonNull(authenticationHolder);
    Objects.nonNull(accessToken);
    setAuthenticationHolder(authenticationHolder);
    setClient(client);
    addAccessToken(accessToken);
  }

  public OAuth2RefreshTokenEntity(ClientDetailsEntity client,
      AuthenticationHolderEntity authenticationHolder, OAuth2AccessTokenEntity accessToken,
      JWT jwtTokenValue) {

    this(client, authenticationHolder, accessToken);
    Objects.nonNull(jwtTokenValue);
    this.tokenValue = jwtTokenValue.serialize();
    this.jwt = jwtTokenValue;
  }

  public OAuth2RefreshTokenEntity(ClientDetailsEntity client,
      AuthenticationHolderEntity authenticationHolder, OAuth2AccessTokenEntity accessToken,
      String tokenValue) {

    this(client, authenticationHolder, accessToken);
    Objects.nonNull(tokenValue);
    try {
      this.jwt = JWTParser.parse(tokenValue);
    } catch (ParseException e) {
      throw new IllegalArgumentException("Invalid token value: " + e.getMessage());
    }
    this.tokenValue = tokenValue;
  }

  public Long getId() {

    return id;
  }

  public AuthenticationHolderEntity getAuthenticationHolder() {

    return authenticationHolder;
  }

  public void setAuthenticationHolder(AuthenticationHolderEntity authenticationHolder) {

    this.authenticationHolder = authenticationHolder;
  }

  // public void setTokenValue(String tokenValue) {
  //
  // Objects.nonNull(tokenValue);
  // this.tokenValue = tokenValue;
  // try {
  // this.jwt = JWTParser.parse(tokenValue);
  // } catch (ParseException e) {
  // throw new IllegalArgumentException("Invalid token value: " + e.getMessage());
  // }
  // }

  @Override
  @Transient
  public String getValue() {

    return tokenValue;
  }

  public Date getExpiration() {

    return expiration;
  }

  public void setExpiration(Date expiration) {

    this.expiration = expiration;
  }

  @Transient
  public boolean isExpired() {

    return getExpiration() == null ? false : System.currentTimeMillis() > getExpiration().getTime();
  }

  public ClientDetailsEntity getClient() {

    return client;
  }

  public void setClient(ClientDetailsEntity client) {

    this.client = client;
  }

  @Transient
  public JWT getJwt() {

    if (jwt == null && tokenValue != null) {
      try {
        jwt = JWTParser.parse(tokenValue);
      } catch (ParseException e) {
        throw new IllegalStateException(e);
      }
    }
    return jwt;
  }

  @Transient
  public Set<OAuth2AccessTokenEntity> getAccessTokens() {
    return accessTokens;
  }

  public void addAccessToken(OAuth2AccessTokenEntity accessToken) {

    accessTokens.add(accessToken);
    accessToken.setRefreshToken(this);
  }
}
