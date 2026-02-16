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
package it.infn.mw.iam.core.oauth.code;

import java.util.Date;

import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.core.AuthenticationHolderService;
import it.infn.mw.iam.persistence.model.AuthenticationHolderEntity;
import it.infn.mw.iam.persistence.model.AuthorizationCodeEntity;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.repository.IamAuthorizationCodeRepository;
import it.infn.mw.iam.persistence.repository.IamClientRepository;
import it.infn.mw.iam.util.SimpleRandomValueStringGenerator;

@SuppressWarnings("deprecation")
@Service
public class IamAuthorizationCodeService implements AuthorizationCodeServices {

  private static final SimpleRandomValueStringGenerator generator = new SimpleRandomValueStringGenerator(22);

  private final IamAuthorizationCodeRepository codeRepository;
  private final ClientService clientService;
  private final AuthenticationHolderService authenticationHolderService;

  /* 5 minutes expiration */
  private final int authCodeExpirationSeconds = 300;

  public IamAuthorizationCodeService(IamAuthorizationCodeRepository codeRepository,
      ClientService clientService, 
      AuthenticationHolderService authenticationHolderService) {

    this.codeRepository = codeRepository;
    this.clientService = clientService;
    this.authenticationHolderService = authenticationHolderService;
  }

  @Override
  @Transactional
  public String createAuthorizationCode(OAuth2Authentication authentication) {

    String code = generator.generate();

    ClientDetailsEntity client =
        clientService.findClientByClientId(authentication.getOAuth2Request().getClientId())
          .orElseThrow(
              () -> new IllegalStateException("Invalid requesting client id: client not found"));

    AuthenticationHolderEntity authHolder = authenticationHolderService.create(client, authentication);

    Date expiration = new Date(System.currentTimeMillis() + (authCodeExpirationSeconds * 1000L));

    AuthorizationCodeEntity entity = new AuthorizationCodeEntity(code, authHolder, expiration);
    authHolder.addAuthorizationCode(entity);

    authenticationHolderService.save(authHolder);
    return code;
  }

  @Override
  public OAuth2Authentication consumeAuthorizationCode(String code) throws InvalidGrantException {

    AuthorizationCodeEntity result = codeRepository.findByCode(code)
      .orElseThrow(
          () -> new InvalidGrantException("No authorization code found for value " + code));

    OAuth2Authentication auth = result.getAuthenticationHolder().getAuthentication();

    codeRepository.delete(result);

    return auth;
  }

}
