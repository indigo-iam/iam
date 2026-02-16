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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

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
import org.springframework.security.oauth2.common.OAuth2AccessTokenJackson2Deserializer;
import org.springframework.security.oauth2.common.OAuth2AccessTokenJackson2Serializer;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

@SuppressWarnings("deprecation")
@Entity
@Table(name = "access_token")
@JsonSerialize(using = OAuth2AccessTokenJackson2Serializer.class)
@JsonDeserialize(using = OAuth2AccessTokenJackson2Deserializer.class)
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

  @Column(name = "token_value", length = 4096)
  private String tokenValue;

  @Transient
  private JWT jwtValue;

  @Column(name = "token_value_hash", length = 64)
  private String tokenValueHash;

  @Column(name = "expiration")
  @Temporal(TemporalType.TIMESTAMP)
  private Date expiration;

  @Column(name = "token_type", length = 256)
  private String tokenType;

  @ManyToOne(optional = false)
  @JoinColumn(name = "refresh_token_id")
  private OAuth2RefreshTokenEntity refreshToken;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(joinColumns = @JoinColumn(name = "owner_id"), name = "token_scope")
  private Set<String> scope;

  @ManyToOne
  @JoinColumn(name = "approved_site_id")
  private ApprovedSite approvedSite;

  @Transient
  private Map<String, Object> additionalInformation;

  @Transient
  private JWT idToken;

  public OAuth2AccessTokenEntity() {

  }

  public OAuth2AccessTokenEntity(ClientDetailsEntity client,
      AuthenticationHolderEntity authenticationHolder) {

    this.client = client;
    this.authenticationHolder = authenticationHolder;
    this.additionalInformation = new HashMap<>();
    this.tokenType = OAuth2AccessToken.BEARER_TYPE;
  }

  public Long getId() {

    return id;
  }

  public void setId(Long id) {

    this.id = id;
  }

  @Override
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

    return getTokenValue();
  }

  public String getTokenValue() {

    return this.tokenValue;
  }

  public void setTokenValue(String tokenValue) {

    Objects.nonNull(tokenValue);
    this.tokenValue = tokenValue;
    this.tokenValueHash = sha256(tokenValue);
    try {
      this.jwtValue = JWTParser.parse(tokenValue);
    } catch (ParseException e) {
      throw new IllegalArgumentException("Invalid token value: " + e.getMessage());
    }
  }

  public void setTokenJwtValue(JWT jwtTokenValue) {

    Objects.nonNull(jwtTokenValue);
    this.jwtValue = jwtTokenValue;
    this.tokenValue = jwtTokenValue.serialize();
    this.tokenValueHash = sha256(tokenValue);
  }

  public String getTokenValueHash() {

    return tokenValueHash;
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

  public void setRefreshToken(OAuth2RefreshToken refreshToken) {

    if (refreshToken instanceof OAuth2RefreshTokenEntity rt) {
      setRefreshToken(rt);
    }
  }

  @Override
  public Set<String> getScope() {

    return scope;
  }

  public void setScope(Set<String> scope) {

    this.scope = scope;
  }

  @Override
  @Transient
  public boolean isExpired() {

    return getExpiration() == null ? false : System.currentTimeMillis() > getExpiration().getTime();
  }

  @Transient
  public JWT getJwt() {

    if (jwtValue == null && tokenValue != null) {
      try {
        jwtValue = JWTParser.parse(tokenValue);
      } catch (ParseException e) {
        throw new IllegalStateException(e);
      }
    }
    return jwtValue;
  }

  @Override
  @Transient
  public int getExpiresIn() {

    if (getExpiration() == null) {
      return -1; // no expiration time
    } else {
      int secondsRemaining =
          (int) ((getExpiration().getTime() - System.currentTimeMillis()) / 1000);
      if (isExpired()) {
        return 0; // has an expiration time and expired
      } else { // has an expiration time and not expired
        return secondsRemaining;
      }
    }
  }

  public ApprovedSite getApprovedSite() {

    return approvedSite;
  }

  public void setApprovedSite(ApprovedSite approvedSite) {

    this.approvedSite = approvedSite;
  }

  @Transient
  public String getIdToken() {

    if (additionalInformation.containsKey(ID_TOKEN_FIELD_NAME)) {
      return additionalInformation.get(ID_TOKEN_FIELD_NAME).toString();
    }
    return null;
  }

  public void setIdToken(JWT idToken) {

    if (idToken == null) {
      return;
    }
    additionalInformation.put(ID_TOKEN_FIELD_NAME, idToken.serialize());
  }

  public static String sha256(String tokenString) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(tokenString.getBytes(StandardCharsets.UTF_8));
      return bytesToHex(hash);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  private static String bytesToHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }
}

