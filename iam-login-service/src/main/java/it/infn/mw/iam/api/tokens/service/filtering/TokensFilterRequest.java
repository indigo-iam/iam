package it.infn.mw.iam.api.tokens.service.filtering;

public interface TokensFilterRequest {

  public String getClientId();

  public String getUserId();
}
