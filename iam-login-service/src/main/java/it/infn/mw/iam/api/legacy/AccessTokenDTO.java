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
package it.infn.mw.iam.api.legacy;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

public class AccessTokenDTO {

  private final Long id;
  private final String value;
  private final Long refreshTokenId;
  private final Set<String> scopes;
  private final String clientId;
  private final String userId;
  private final Date expiration;

  private AccessTokenDTO(Long id, String value, Long refreshTokenId, Set<String> scopes,
      String clientId, String userId, Date expiration) {
    this.id = id;
    this.value = value;
    this.refreshTokenId = refreshTokenId;
    this.scopes = scopes;
    this.clientId = clientId;
    this.userId = userId;
    this.expiration = expiration;
  }

  public Long getId() {
    return id;
  }

  public String getValue() {
    return value;
  }

  public Long getRefreshTokenId() {
    return refreshTokenId;
  }

  public Set<String> getScopes() {
    return scopes;
  }

  public String getClientId() {
    return clientId;
  }

  public String getUserId() {
    return userId;
  }

  public Date getExpiration() {
    return expiration;
  }

  public static class Builder {
    private Long id;
    private String value;
    private Long refreshTokenId;
    private Set<String> scopes;
    private String clientId;
    private String userId;
    private Date expiration;

    private Builder() {}

    public Builder id(Long id) {
      this.id = id;
      return this;
    }

    public Builder value(String value) {
      this.value = value;
      return this;
    }

    public Builder refreshTokenId(Long refreshTokenId) {
      this.refreshTokenId = refreshTokenId;
      return this;
    }

    public Builder scopes(Set<String> scopes) {
      this.scopes = new HashSet<>();
      this.scopes.addAll(scopes);
      return this;
    }

    public Builder clientId(String clientId) {
      this.clientId = clientId;
      return this;
    }

    public Builder userId(String userId) {
      this.userId = userId;
      return this;
    }

    public Builder expiration(Date expiration) {
      this.expiration = expiration;
      return this;
    }

    public AccessTokenDTO build() {
      return new AccessTokenDTO(id, value, refreshTokenId, scopes, clientId, userId, expiration);
    }
  }

  public static Builder builder() {
    return new Builder();
  }
}
