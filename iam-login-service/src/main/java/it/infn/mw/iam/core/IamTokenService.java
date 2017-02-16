package it.infn.mw.iam.core;

import java.util.Set;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

import com.google.common.collect.Sets;

import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;

@Service("defaultOAuth2ProviderTokenService")
@Primary
public class IamTokenService extends DefaultOAuth2ProviderTokenService {

  private final IamOAuthAccessTokenRepository accessTokenRepo;
  private final IamOAuthRefreshTokenRepository refreshTokenRepo;

  @Autowired
  public IamTokenService(IamOAuthAccessTokenRepository atRepo,
      IamOAuthRefreshTokenRepository rtRepo) {
    this.accessTokenRepo = atRepo;
    this.refreshTokenRepo = rtRepo;
  }


  @Override
  public Set<OAuth2AccessTokenEntity> getAllAccessTokensForUser(String id) {

    Set<OAuth2AccessTokenEntity> results = Sets.newLinkedHashSet();
    results.addAll(accessTokenRepo.findValidAccessTokensForUser(id));
    return results;
  }


  @Override
  public Set<OAuth2RefreshTokenEntity> getAllRefreshTokensForUser(String id) {
    Set<OAuth2RefreshTokenEntity> results = Sets.newLinkedHashSet();
    results.addAll(refreshTokenRepo.findValidRefreshTokensForUser(id));
    return results;
  }

  @Override
  public void revokeAccessToken(OAuth2AccessTokenEntity accessToken) {
    accessTokenRepo.delete(accessToken);
  }

  @Override
  public void revokeRefreshToken(OAuth2RefreshTokenEntity refreshToken) {
    refreshTokenRepo.delete(refreshToken);
  }

}
