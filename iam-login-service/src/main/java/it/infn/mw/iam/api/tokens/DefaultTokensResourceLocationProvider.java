package it.infn.mw.iam.api.tokens;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class DefaultTokensResourceLocationProvider implements TokensResourceLocationProvider {

  public static final String ACCESS_TOKENS_API_ENDPOINT = "/access-tokens";
  public static final String REFRESH_TOKENS_API_ENDPOINT = "/refresh-tokens";

  @Value("${iam.baseUrl}")
  private String baseUrl;

  @Override
  public String accessTokenLocation(Long accessTokenId) {
    return String.format("%s%s/%d", baseUrl, ACCESS_TOKENS_API_ENDPOINT, accessTokenId);
  }

  @Override
  public String refreshTokenLocation(Long refreshTokenId) {
    return String.format("%s%s/%d", baseUrl, REFRESH_TOKENS_API_ENDPOINT, refreshTokenId);
  }

}
