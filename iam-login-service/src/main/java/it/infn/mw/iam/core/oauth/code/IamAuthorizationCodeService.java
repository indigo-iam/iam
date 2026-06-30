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

import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;

import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.AuthorizationCodeEntity;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.core.IamAuthenticationHolderEntityService;
import it.infn.mw.iam.persistence.repository.IamAuthorizationCodeRepository;

@SuppressWarnings("deprecation")
@Service
public class IamAuthorizationCodeService implements AuthorizationCodeServices {

  private final Clock clock;
  private final IamAuthorizationCodeRepository codeRepository;
  private final IamAuthenticationHolderEntityService authenticationHolderService;
  private final SecureRandom random;

  public IamAuthorizationCodeService(Clock clock, IamAuthorizationCodeRepository codeRepository,
      IamAuthenticationHolderEntityService authenticationHolderService, SecureRandom random) {

    this.clock = clock;
    this.codeRepository = codeRepository;
    this.authenticationHolderService = authenticationHolderService;
    this.random = random;
  }

  private String generateToken() {

    byte[] bytes = new byte[16];
    random.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  @Override
  public String createAuthorizationCode(OAuth2Authentication authentication) {

    String code = generateToken();
    AuthenticationHolderEntity authHolder = authenticationHolderService.create(authentication);
    Date expiration = Date.from(clock.instant().plusSeconds(300));
    AuthorizationCodeEntity entity = new AuthorizationCodeEntity(code, authHolder, expiration);

    codeRepository.save(entity);
    return code;
  }

  @Override
  public OAuth2Authentication consumeAuthorizationCode(String code) throws InvalidGrantException {

    Optional<AuthorizationCodeEntity> authzCode = codeRepository.findByCode(code);

    if (authzCode.isEmpty()) {
      throw new InvalidGrantException(
          "JpaAuthorizationCodeRepository: no authorization code found for value " + code);
    }

    OAuth2Authentication savedAuth = authzCode.get().getAuthenticationHolder().getAuthentication();
    codeRepository.delete(authzCode.get());

    return savedAuth;
  }

}
