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
package it.infn.mw.iam.core.oauth;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;

import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.AuthorizationCodeEntity;
import org.mitre.oauth2.repository.AuthorizationCodeRepository;
import org.mitre.oauth2.service.AuthenticationHolderEntityService;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class IamAuthorizationCodeService implements AuthorizationCodeServices {

  private static final int CODE_BYTES_LENGTH = 22;
  private static final int CODE_EXPIRATION_IN_SECS = 300;

  private static final SecureRandom secureRandom = new SecureRandom();
  private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding();

  public static String generateRandomString(int byteLength) {
    byte[] randomBytes = new byte[byteLength];
    secureRandom.nextBytes(randomBytes);
    return base64Encoder.encodeToString(randomBytes);
  }

  private AuthorizationCodeRepository authorizationCodeRepo;
  private AuthenticationHolderEntityService authenticationHolderService;

  public IamAuthorizationCodeService(AuthorizationCodeRepository authorizationCodeRepo,
      AuthenticationHolderEntityService authenticationHolderService) {
    this.authorizationCodeRepo = authorizationCodeRepo;
    this.authenticationHolderService = authenticationHolderService;
  }

  @Override
  @Transactional(value = "defaultTransactionManager")
  public String createAuthorizationCode(OAuth2Authentication authentication) {

    String code = generateRandomString(CODE_BYTES_LENGTH);
    AuthenticationHolderEntity authHolder = authenticationHolderService.create(authentication);
    Date expiration = new Date(System.currentTimeMillis() + (CODE_EXPIRATION_IN_SECS * 1000L));
    AuthorizationCodeEntity entity = new AuthorizationCodeEntity(code, authHolder, expiration);
    authorizationCodeRepo.save(entity);
    return code;
  }

  @Override
  public OAuth2Authentication consumeAuthorizationCode(String code) throws InvalidGrantException {

    AuthorizationCodeEntity result = authorizationCodeRepo.getByCode(code);
    if (result == null) {
      throw new InvalidGrantException(
          "JpaAuthorizationCodeRepository: no authorization code found for value " + code);
    }
    OAuth2Authentication auth = result.getAuthenticationHolder().getAuthentication();
    authorizationCodeRepo.remove(result);
    return auth;
  }

}
