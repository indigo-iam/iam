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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.oauth.code.IamAuthorizationCodeService;
import it.infn.mw.iam.persistence.repository.IamAuthenticationHolderRepository;
import it.infn.mw.iam.persistence.repository.IamAuthorizationCodeRepository;

@SuppressWarnings("deprecation")
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
class AuthorizationCodeAtomicityTests {

  @Autowired
  IamAuthorizationCodeService service;

  @Autowired
  IamAuthenticationHolderRepository holderRepo;

  @MockBean
  IamAuthorizationCodeRepository codeRepo;

  @Test
  void noAuthenticationHolderIsLeftBehindWhenTheCodeIsNotSaved() {

    when(codeRepo.save(any())).thenThrow(new DataIntegrityViolationException("not saved"));

    OAuth2Request request = new OAuth2Request(Map.of(), "client", Set.of(), true,
        Set.of("openid"), Set.of(), "https://example.org/callback", Set.of(), Map.of());
    OAuth2Authentication authentication =
        new OAuth2Authentication(request, new UsernamePasswordAuthenticationToken("test", "",
            List.of(new SimpleGrantedAuthority("ROLE_USER"))));

    long holders = holderRepo.count();

    assertThrows(DataIntegrityViolationException.class,
        () -> service.createAuthorizationCode(authentication));
    assertEquals(holders, holderRepo.count());
  }
}
