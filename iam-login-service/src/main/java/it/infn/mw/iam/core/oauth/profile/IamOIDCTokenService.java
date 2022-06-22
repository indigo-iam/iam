/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.infn.mw.iam.core.oauth.profile;

import static org.mitre.openid.connect.request.ConnectRequestParameters.MAX_AGE;
import static org.mitre.openid.connect.request.ConnectRequestParameters.NONCE;

import java.time.Clock;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.ClientKeyCacheService;
import org.mitre.jwt.signer.service.impl.SymmetricKeyJWTValidatorCacheService;
import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.repository.AuthenticationHolderRepository;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.openid.connect.config.ConfigurationPropertiesBean;
import org.mitre.openid.connect.service.OIDCTokenService;
import org.mitre.openid.connect.util.IdTokenHashUtils;
import org.mitre.openid.connect.web.AuthenticationTimeStamper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.stereotype.Service;

import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;
import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.api.common.error.NoSuchAccountError;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Service
@Primary
@SuppressWarnings("deprecation")
public class IamOIDCTokenService implements OIDCTokenService {

  public static final Logger LOG = LoggerFactory.getLogger(IamOIDCTokenService.class);

  private final Clock clock;
  private final JWTProfileResolver profileResolver;
  private final IamAccountRepository accountRepository;
  private final JWTSigningAndValidationService jwtService;
  private final AuthenticationHolderRepository authenticationHolderRepository;
  private final ConfigurationPropertiesBean configBean;
  private final ClientKeyCacheService encrypters;
  private final SymmetricKeyJWTValidatorCacheService symmetricCacheService;
  private final OAuth2TokenEntityService tokenService;

  public IamOIDCTokenService(Clock clock, JWTProfileResolver profileResolver,
      IamAccountRepository accountRepository, JWTSigningAndValidationService jwtService,
      AuthenticationHolderRepository authenticationHolderRepository,
      ConfigurationPropertiesBean configBean, ClientKeyCacheService encrypters,
      SymmetricKeyJWTValidatorCacheService symmetricCacheService,
      OAuth2TokenEntityService tokenService) {
    this.clock = clock;
    this.profileResolver = profileResolver;
    this.accountRepository = accountRepository;
    this.jwtService = jwtService;
    this.authenticationHolderRepository = authenticationHolderRepository;
    this.configBean = configBean;
    this.encrypters = encrypters;
    this.symmetricCacheService = symmetricCacheService;
    this.tokenService = tokenService;
  }


  protected void addCustomIdTokenClaims(Builder idClaims, ClientDetailsEntity client,
      OAuth2Request request, String sub, OAuth2AccessTokenEntity accessToken) {

    IamAccount account =
        accountRepository.findByUuid(sub).orElseThrow(() -> NoSuchAccountError.forUuid(sub));

    JWTProfile profile = profileResolver.resolveProfile(client.getClientId());

    profile.getIDTokenCustomizer()
      .customizeIdTokenClaims(idClaims, client, request, sub, accessToken, account);
  }


  private void handleAuthTimestamp(ClientDetailsEntity client, OAuth2Request request,
      JWTClaimsSet.Builder idClaims) {

    if (request.getExtensions().containsKey(MAX_AGE)
        || (client.getRequireAuthTime() != null && client.getRequireAuthTime())) {

      if (request.getExtensions().get(AuthenticationTimeStamper.AUTH_TIMESTAMP) != null) {
        Long authTimestamp = Long.parseLong(
            (String) request.getExtensions().get(AuthenticationTimeStamper.AUTH_TIMESTAMP));
        if (authTimestamp != null) {
          idClaims.claim("auth_time", authTimestamp / 1000L);
        }
      } else {
        LOG.debug("Unable to find authentication timestamp while creating ID token");
      }
    }

  }

  @Override
  public JWT createIdToken(ClientDetailsEntity client, OAuth2Request request, Date issueTime,
      String sub, OAuth2AccessTokenEntity accessToken) {


    JWSAlgorithm signingAlg = jwtService.getDefaultSigningAlgorithm();

    if (client.getIdTokenSignedResponseAlg() != null) {
      signingAlg = client.getIdTokenSignedResponseAlg();
    }

    JWT idToken = null;
    JWTClaimsSet.Builder idClaims = new JWTClaimsSet.Builder();

    idClaims.issuer(configBean.getIssuer());
    idClaims.subject(sub);
    idClaims.audience(Lists.newArrayList(client.getClientId()));
    idClaims.jwtID(UUID.randomUUID().toString());

    idClaims.issueTime(issueTime);
    handleAuthTimestamp(client, request, idClaims);

    if (client.getIdTokenValiditySeconds() != null) {
      Date expiration =
          new Date(System.currentTimeMillis() + (client.getIdTokenValiditySeconds() * 1000L));
      idClaims.expirationTime(expiration);
    }

    String nonce = (String) request.getExtensions().get(NONCE);
    if (!Strings.isNullOrEmpty(nonce)) {
      idClaims.claim("nonce", nonce);
    }

    Set<String> responseTypes = request.getResponseTypes();

    if (responseTypes.contains("token")) {
      Base64URL atHash = IdTokenHashUtils.getAccessTokenHash(signingAlg, accessToken);
      idClaims.claim("at_hash", atHash);
    }

    addCustomIdTokenClaims(idClaims, client, request, sub, accessToken);

    if (clientWantsEncryptedIdTokens(client)) {

      JWTEncryptionAndDecryptionService encrypter =
          Optional.ofNullable(encrypters.getEncrypter(client)).orElseThrow();

      JWEHeader header = new JWEHeader.Builder(client.getIdTokenEncryptedResponseAlg(),
          client.getIdTokenEncryptedResponseEnc()).build();
      idToken = new EncryptedJWT(header, idClaims.build());
      encrypter.encryptJwt((JWEObject) idToken);

    } else {

      JWSHeader header =
          new JWSHeader.Builder(signingAlg).keyID(jwtService.getDefaultSignerKeyId()).build();

      if (JWSAlgorithm.Family.HMAC_SHA.contains(signingAlg)) {
        idToken = new SignedJWT(header, idClaims.build());
        JWTSigningAndValidationService signer =
            Optional.ofNullable(symmetricCacheService.getSymmetricValidtor(client)).orElseThrow();
        signer.signJwt((SignedJWT) idToken);
      } else {
        idClaims.claim("kid", jwtService.getDefaultSignerKeyId());
        idToken = new SignedJWT(header, idClaims.build());
        jwtService.signJwt((SignedJWT) idToken);
      }
    }

    return idToken;
  }


  private boolean clientWantsEncryptedIdTokens(ClientDetailsEntity client) {
    return client.getIdTokenEncryptedResponseAlg() != null
        && !client.getIdTokenEncryptedResponseAlg().equals(Algorithm.NONE)
        && client.getIdTokenEncryptedResponseEnc() != null
        && !client.getIdTokenEncryptedResponseEnc().equals(Algorithm.NONE)
        && (!Strings.isNullOrEmpty(client.getJwksUri()) || client.getJwks() != null);
  }


  @Override
  public OAuth2AccessTokenEntity createRegistrationAccessToken(ClientDetailsEntity client) {
    return buildRegistrationAccessToken(client,
        Sets.newHashSet(SystemScopeService.REGISTRATION_TOKEN_SCOPE));
  }



  @Override
  public OAuth2AccessTokenEntity createResourceAccessToken(ClientDetailsEntity client) {
    return buildRegistrationAccessToken(client,
        Sets.newHashSet(SystemScopeService.RESOURCE_TOKEN_SCOPE));
  }



  @Override
  public OAuth2AccessTokenEntity rotateRegistrationAccessTokenForClient(
      ClientDetailsEntity client) {

    OAuth2AccessTokenEntity oldToken = tokenService.getRegistrationAccessTokenForClient(client);
    if (oldToken != null) {
      Set<String> scope = oldToken.getScope();
      tokenService.revokeAccessToken(oldToken);
      return buildRegistrationAccessToken(client, scope);
    } else {
      return null;
    }
  }

  private OAuth2AccessTokenEntity buildRegistrationAccessToken(ClientDetailsEntity client,
      Set<String> scope) {
    OAuth2AccessTokenEntity oldToken = tokenService.getRegistrationAccessTokenForClient(client);
    if (oldToken != null) {
      tokenService.revokeAccessToken(oldToken);
    }

    Map<String, String> authorizationParameters = Maps.newHashMap();
    OAuth2Request clientAuth = new OAuth2Request(authorizationParameters, client.getClientId(),
        Sets.newHashSet(Authorities.ROLE_CLIENT), true, scope, null, null, null,
        null);

    OAuth2Authentication authentication = new OAuth2Authentication(clientAuth, null);

    OAuth2AccessTokenEntity token = new OAuth2AccessTokenEntity();
    token.setClient(client);
    token.setScope(scope);

    AuthenticationHolderEntity authHolder = new AuthenticationHolderEntity();
    authHolder.setAuthentication(authentication);
    authHolder = authenticationHolderRepository.save(authHolder);
    token.setAuthenticationHolder(authHolder);

    JWTClaimsSet claims =
        new JWTClaimsSet.Builder().audience(Lists.newArrayList(client.getClientId()))
          .issuer(configBean.getIssuer())
          .issueTime(Date.from(clock.instant()))
          .jwtID(UUID.randomUUID().toString())
          .build();

    JWSAlgorithm signingAlg = jwtService.getDefaultSigningAlgorithm();
    JWSHeader header =
        new JWSHeader.Builder(signingAlg).keyID(jwtService.getDefaultSignerKeyId()).build();
    SignedJWT signed = new SignedJWT(header, claims);

    jwtService.signJwt(signed);

    token.setJwt(signed);

    return token;

  }
}
