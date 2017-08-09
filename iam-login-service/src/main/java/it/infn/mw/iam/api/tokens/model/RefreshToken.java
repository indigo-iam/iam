package it.infn.mw.iam.api.tokens.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFilter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Date;
import java.util.Set;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonFilter("attributeFilter")
public class RefreshToken   {

  private Long id;
  private String value;
  private Set<String> scopes;
  private Date expiration;
  private ClientRef client;
  private UserRef user;

  @JsonCreator
  public RefreshToken(@JsonProperty("id") Long id, @JsonProperty("value") String value,
      @JsonProperty("scopes") Set<String> scopes, @JsonProperty("expiration") Date expiration,
      @JsonProperty("client") ClientRef client, @JsonProperty("user") UserRef user) {

    this.id = id;
    this.value = value;
    this.scopes = scopes;
    this.expiration = expiration;
    this.client = client;
    this.user = user;
  }

  public RefreshToken(Builder builder) {

    this.id = builder.id;
    this.value = builder.value;
    this.scopes = builder.scopes;
    this.expiration = builder.expiration;
    this.client = builder.client;
    this.user = builder.user;
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

    public RefreshToken build() {
      return new RefreshToken(this);
    }
  }
}

