package it.infn.mw.iam.api.tokens.service.filtering;

public class DefaultTokensFilterRequest implements TokensFilterRequest {

  private final String clientId;
  private final String userId;

  private DefaultTokensFilterRequest(Builder b) {
    this.clientId = b.clientId;
    this.userId = b.userId;
  }

  @Override
  public String getClientId() {
    return clientId;
  }

  @Override
  public String getUserId() {
    return userId;
  }

  public static class Builder {

    private String clientId;
    private String userId;

    public Builder clientId(String clientId) {

      this.clientId = clientId;
      return this;
    }

    public Builder userId(String userId) {

      this.userId = userId;
      return this;
    }

    public DefaultTokensFilterRequest build() {

      return new DefaultTokensFilterRequest(this);
    }
  }
}
