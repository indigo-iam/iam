package it.infn.mw.iam.api.tokens.converter;

import it.infn.mw.iam.api.scim.converter.ScimResourceLocationProvider;
import it.infn.mw.iam.api.tokens.TokensResourceLocationProvider;
import it.infn.mw.iam.api.tokens.model.AccessToken;
import it.infn.mw.iam.api.tokens.model.ClientRef;
import it.infn.mw.iam.api.tokens.model.IdTokenRef;
import it.infn.mw.iam.api.tokens.model.RefreshToken;
import it.infn.mw.iam.api.tokens.model.UserRef;
import it.infn.mw.iam.core.user.exception.IamAccountException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class TokensConverter {

  @Autowired
  private ClientDetailsEntityService clientDetailsService;

  @Autowired
  private IamAccountRepository accountRepository;

  @Autowired
  private TokensResourceLocationProvider tokensResourceLocationProvider;

  @Autowired
  private ScimResourceLocationProvider scimResourceLocationProvider;

  public AccessToken toAccessToken(OAuth2AccessTokenEntity at) {

    AuthenticationHolderEntity ah = at.getAuthenticationHolder();
    ClientDetailsEntity cd = clientDetailsService.loadClientByClientId(ah.getClientId());
    String username = ah.getAuthentication().getPrincipal().toString();
    IamAccount account = accountRepository.findByUsername(username)
        .orElseThrow(() -> new IamAccountException("Account not found"));

    IdTokenRef idToken = null;

    if (at.getIdToken() != null) {
      Long idTokenId = at.getIdToken().getId();
      idToken = IdTokenRef.builder()
          .id(idTokenId)
          .ref(tokensResourceLocationProvider.accessTokenLocation(idTokenId))
          .build();
    }

    return AccessToken.builder()
        .id(at.getId())
        .client(ClientRef.builder()
            .id(cd.getId())
            .clientId(cd.getClientId())
            .contacts(cd.getContacts())
            .ref(cd.getClientUri())
            .build())
        .expiration(at.getExpiration())
        .idToken(idToken)
        .scopes(ah.getScope())
        .user(UserRef.builder()
            .id(account.getUuid())
            .userName(account.getUsername())
            .ref(scimResourceLocationProvider.userLocation(account.getUuid()))
            .build())
        .value(at.getValue())
        .build();
  }

  public RefreshToken toRefreshToken(OAuth2RefreshTokenEntity at) {

    AuthenticationHolderEntity ah = at.getAuthenticationHolder();
    ClientDetailsEntity cd = clientDetailsService.loadClientByClientId(ah.getClientId());
    String username = ah.getAuthentication().getPrincipal().toString();
    IamAccount account = accountRepository.findByUsername(username)
        .orElseThrow(() -> new IamAccountException("Account not found"));

    return RefreshToken.builder()
        .id(at.getId())
        .client(ClientRef.builder()
            .id(cd.getId())
            .clientId(cd.getClientId())
            .contacts(cd.getContacts())
            .ref(cd.getClientUri())
            .build())
        .expiration(at.getExpiration())
        .scopes(ah.getScope())
        .user(UserRef.builder()
            .id(account.getUuid())
            .userName(account.getUsername())
            .ref(scimResourceLocationProvider.userLocation(account.getUuid()))
            .build())
        .value(at.getValue())
        .build();
  }
}
