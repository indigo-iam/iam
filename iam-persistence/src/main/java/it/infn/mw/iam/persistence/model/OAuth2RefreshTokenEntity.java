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

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.Transient;

import org.springframework.security.oauth2.common.OAuth2RefreshToken;

import com.nimbusds.jwt.PlainJWT;

@SuppressWarnings("deprecation")
@Entity
@Table(name = "refresh_token")
public class OAuth2RefreshTokenEntity implements OAuth2RefreshToken {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "id")
  private Long id;

  @ManyToOne
  @JoinColumn(name = "auth_holder_id")
  private AuthenticationHolderEntity authenticationHolder;

  @ManyToOne(fetch = FetchType.EAGER)
  @JoinColumn(name = "client_id")
  private ClientDetailsEntity client;

  @Column(name = "token_value")
  private String value;

  @Temporal(javax.persistence.TemporalType.TIMESTAMP)
  @Column(name = "expiration")
  private Date expiration;

  public OAuth2RefreshTokenEntity() {
    // Empty constructor
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public AuthenticationHolderEntity getAuthenticationHolder() {
    return authenticationHolder;
  }

  public void setAuthenticationHolder(AuthenticationHolderEntity authenticationHolder) {
    this.authenticationHolder = authenticationHolder;
  }

  @Override
  public String getValue() {
    return value;
  }

  public void setValue(String value) {
    this.value = value;
  }

  public Date getExpiration() {
    return expiration;
  }

  public void setExpiration(Date expiration) {
    this.expiration = expiration;
  }

  public ClientDetailsEntity getClient() {
    return client;
  }

  public void setClient(ClientDetailsEntity client) {
    this.client = client;
  }

  @Transient
  public PlainJWT getJwt() {
    try {
      return PlainJWT.parse(value);
    } catch (ParseException e) {
      return null;
    }
  }

}
