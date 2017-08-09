package it.infn.mw.iam.api.tokens;

public interface TokensResourceLocationProvider {

  public String accessTokenLocation(Long accessTokenId);

  public String refreshTokenLocation(Long refreshTokenId);
}
