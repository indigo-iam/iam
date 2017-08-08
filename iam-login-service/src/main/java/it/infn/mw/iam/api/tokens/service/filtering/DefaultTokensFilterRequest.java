package it.infn.mw.iam.api.tokens.service.filtering;

import java.util.Optional;

public class DefaultTokensFilterRequest implements TokensFilterRequest {

  private final Optional<String> clientId;
  private final Optional<String> userId;

  private DefaultTokensFilterRequest(Builder b) {
    this.clientId = b.clientId;
    this.userId = b.userId;
  }

  @Override
  public Optional<String> getClientId() {
    return clientId;
  }

  @Override
  public Optional<String> getUserId() {
    return userId;
  }

  public static class Builder {

    private Optional<String> clientId = Optional.empty();
    private Optional<String> userId = Optional.empty();

    public Builder clientId(Optional<String> clientId) {

      this.clientId = clientId;
      return this;
    }

    public Builder userId(Optional<String> userId) {

      this.userId = userId;
      return this;
    }

    public DefaultTokensFilterRequest build() {

      return new DefaultTokensFilterRequest(this);
    }
  }
}
