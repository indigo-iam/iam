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
package it.infn.mw.iam.api.tokens.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFilter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Date;
import java.util.Set;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonFilter("attributeFilter")
public class AccessToken {

  private Long id;
  private String value;
  private Set<String> scopes;
  private Date expiration;
  private ClientRef client;
  private UserRef user;
  private IdTokenRef idToken;

  @JsonCreator
  public AccessToken(@JsonProperty("id") Long id, @JsonProperty("value") String value,
      @JsonProperty("scopes") Set<String> scopes, @JsonProperty("expiration") Date expiration,
      @JsonProperty("client") ClientRef client, @JsonProperty("user") UserRef user,
      @JsonProperty("idToken") IdTokenRef idToken) {

    this.id = id;
    this.value = value;
    this.scopes = scopes;
    this.expiration = expiration;
    this.client = client;
    this.user = user;
    this.idToken = idToken;
  }

  public AccessToken(Builder builder) {

    this.id = builder.id;
    this.value = builder.value;
    this.scopes = builder.scopes;
    this.expiration = builder.expiration;
    this.client = builder.client;
    this.user = builder.user;
    this.idToken = builder.idToken;
  }

  @JsonProperty("id")
  public Long getId() {

    return id;
  }

  @JsonProperty("value")
  public String getValue() {

    return value;
  }

  @JsonProperty("scopes")
  public Set<String> getScopes() {

    return scopes;
  }

  @JsonProperty("expiration")
  public Date getExpiration() {

    return expiration;
  }

  @JsonProperty("client")
  public ClientRef getClient() {

    return client;
  }

  @JsonProperty("user")
  public UserRef getUser() {

    return user;
  }

  @JsonProperty("idToken")
  public IdTokenRef getIdToken() {

    return idToken;
  }

  @Override
  public String toString() {
    return "AccessToken [id=" + id + ", value=" + value + ", scopes=" + scopes + ", expiration="
        + expiration + ", client=" + client + ", user=" + user + ", idToken=" + idToken + "]";
  }

  public static Builder builder() {

    return new Builder();
  }

  public static class Builder {

    private Long id;
    private String value;
    private Set<String> scopes;
    private Date expiration;
    private ClientRef client;
    private UserRef user;
    private IdTokenRef idToken;

    public Builder id(Long id) {
      this.id = id;
      return this;
    }

    public Builder value(String value) {
      this.value = value;
      return this;
    }

    public Builder scopes(Set<String> scopes) {
      this.scopes = scopes;
      return this;
    }

    public Builder expiration(Date expiration) {
      this.expiration = expiration;
      return this;
    }

    public Builder client(ClientRef client) {
      this.client = client;
      return this;
    }

    public Builder user(UserRef user) {
      this.user = user;
      return this;
    }

    public Builder idToken(IdTokenRef idToken) {
      this.idToken = idToken;
      return this;
    }

    public AccessToken build() {
      return new AccessToken(this);
    }
  }
}
