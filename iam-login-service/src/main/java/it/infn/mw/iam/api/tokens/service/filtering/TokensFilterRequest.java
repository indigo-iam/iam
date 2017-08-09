package it.infn.mw.iam.api.tokens.service.filtering;

import java.util.Optional;

public interface TokensFilterRequest {

  public Optional<String> getClientId();

  public Optional<String> getUserId();
}
