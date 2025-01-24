package it.infn.mw.iam.api.client.management.service;

import java.util.List;
import java.util.Set;

import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

import it.infn.mw.iam.persistence.model.IamAccessToken;
import it.infn.mw.iam.persistence.model.IamAuthenticationHolder;
import it.infn.mw.iam.persistence.model.IamClient;
import it.infn.mw.iam.persistence.model.IamRefreshToken;

@SuppressWarnings("deprecation")
public interface OAuth2TokenService extends AuthorizationServerTokenServices, ResourceServerTokenServices {

    @Override
    public IamAccessToken readAccessToken(String accessTokenValue);

    public IamRefreshToken getRefreshToken(String refreshTokenValue);

    public void revokeRefreshToken(IamRefreshToken refreshToken);

    public void revokeAccessToken(IamAccessToken accessToken);

    public List<IamAccessToken> getAccessTokensForClient(IamClient client);

    public List<IamRefreshToken> getRefreshTokensForClient(IamClient client);

    public void clearExpiredTokens();

    public IamAccessToken saveAccessToken(IamAccessToken accessToken);

    public IamRefreshToken saveRefreshToken(IamRefreshToken refreshToken);

    @Override
    public IamAccessToken getAccessToken(OAuth2Authentication authentication);

    public IamAccessToken getAccessTokenById(Long id);

    public IamRefreshToken getRefreshTokenById(Long id);

    public List<IamAccessToken> getAllAccessTokensForUser(String name);

    public List<IamRefreshToken> getAllRefreshTokensForUser(String name);

    public IamAccessToken getRegistrationAccessTokenForClient(IamClient client);

    public IamRefreshToken createRefreshToken(IamClient client, IamAuthenticationHolder authHolder);

}
