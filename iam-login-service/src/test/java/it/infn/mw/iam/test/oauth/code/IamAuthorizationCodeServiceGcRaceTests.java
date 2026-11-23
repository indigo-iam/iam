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
package it.infn.mw.iam.test.oauth.code;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;

import java.util.Date;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.dao.InvalidDataAccessApiUsageException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.IamAuthenticationHolderService;
import it.infn.mw.iam.core.gc.GarbageCollector;
import it.infn.mw.iam.core.oauth.code.IamAuthorizationCodeService;
import it.infn.mw.iam.persistence.model.AuthenticationHolderEntity;
import it.infn.mw.iam.persistence.model.AuthorizationCodeEntity;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.repository.IamAuthenticationHolderRepository;
import it.infn.mw.iam.persistence.repository.IamAuthorizationCodeRepository;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;

@SuppressWarnings("deprecation")
@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class, ClockConfig.class},
    webEnvironment = WebEnvironment.MOCK)
class IamAuthorizationCodeServiceGcRaceTests {

  static final String CLIENT_ID = "password-grant";

  @SpyBean
  IamAuthorizationCodeService authorizationCodeService;

  @Autowired
  IamAuthenticationHolderService authenticationHolderService;

  @Autowired
  IamAuthenticationHolderRepository authenticationHolderRepo;

  @SpyBean
  IamAuthorizationCodeRepository codeRepository;

  @Autowired
  GarbageCollector garbageCollector;

  @Autowired
  IamClientRepository clientRepository;

  @Test
  void authorizationCodeCreationFailsWhenGcSweepsHolderBetweenTheTwoTransactions() {

    ClientDetailsEntity client = clientRepository.findByClientId(CLIENT_ID).orElseThrow();

    OAuth2Request request = new OAuth2Request(Map.of(), CLIENT_ID, null, true, Set.of("openid"),
        null, null, null, null);
    OAuth2Authentication authentication = new OAuth2Authentication(request, null);

    AuthenticationHolderEntity authHolder =
        authenticationHolderService.createAndSave(authentication, client);
    assertTrue(authenticationHolderRepo.findById(authHolder.getId()).isPresent());

    garbageCollector.clearOrphanedAuthenticationHolder(100);
    assertTrue(authenticationHolderRepo.findById(authHolder.getId()).isEmpty(),
        "The holder must have been swept as an orphan to reproduce the race");

    AuthorizationCodeEntity entity =
        new AuthorizationCodeEntity("test-code", authHolder, new Date());

    InvalidDataAccessApiUsageException ex = assertThrows(InvalidDataAccessApiUsageException.class,
        () -> codeRepository.save(entity));

    assertThat(ex.getMostSpecificCause().getMessage(),
        containsString("not marked cascade PERSIST"));
  }

  @Test
  void createAuthorizationCodeIsAtomicSoGcCanNeverRaceIt() {

    OAuth2Request request = new OAuth2Request(Map.of(), CLIENT_ID, null, true, Set.of("openid"),
        null, null, null, null);
    OAuth2Authentication authentication = new OAuth2Authentication(request, null);

    String code = authorizationCodeService.createAuthorizationCode(authentication);
    assertNotNull(code);

    AuthorizationCodeEntity saved = codeRepository.findByCode(code).orElseThrow();
    Long holderId = saved.getAuthenticationHolder().getId();

    try {
      garbageCollector.clearOrphanedAuthenticationHolder(100);

      assertFalse(authenticationHolderRepo.findById(holderId).isEmpty(),
          "The holder backing a live authorization code must never be swept as an orphan");
    } finally {
      codeRepository.delete(saved);
      authenticationHolderRepo.findById(holderId).ifPresent(authenticationHolderRepo::delete);
    }
  }

  @Test
  void failedAuthorizationCodeSaveRollsBackAuthenticationHolder() {

    OAuth2Request request = new OAuth2Request(Map.of(), CLIENT_ID, null, true, Set.of("openid"),
        null, null, null, null);
    OAuth2Authentication authentication = new OAuth2Authentication(request, null);

    long holdersBefore = authenticationHolderRepo.count();

    doThrow(new IllegalStateException("Simulated authorization code save failure"))
      .when(codeRepository).save(any(AuthorizationCodeEntity.class));

    try {
      IllegalStateException ex = assertThrows(IllegalStateException.class,
          () -> authorizationCodeService.createAuthorizationCode(authentication));
      assertEquals("Simulated authorization code save failure", ex.getMessage());
    } finally {
      reset(codeRepository);
    }

    assertEquals(holdersBefore, authenticationHolderRepo.count(),
        "The authentication holder must be rolled back if saving the authorization code fails");
  }
}
