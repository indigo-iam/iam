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
package it.infn.mw.iam.test.ext_authn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.SavedUserAuthentication;
import org.mitre.oauth2.repository.AuthenticationHolderRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

@SpringBootTest
class SavedUserAuthenticationTests {

  @Autowired
  private AuthenticationHolderRepository authHolderRepo;

  @Test
  void testMultipleCaseSensitiveAdditionalInfoAreInserted() {
    SavedUserAuthentication userAuth =
        new SavedUserAuthentication(new UsernamePasswordAuthenticationToken("test", "password"));
    userAuth.setAdditionalInfo(Map.of("MAIL", "mail@example.com", "mail", "another@example.com"));
    AuthenticationHolderEntity authHolder = new AuthenticationHolderEntity();
    authHolder.setUserAuth(userAuth);
    assertTrue(authHolder.getUserAuth().getAdditionalInfo().containsKey("MAIL"));
    assertTrue(authHolder.getUserAuth().getAdditionalInfo().containsKey("mail"));
    assertEquals("mail@example.com", authHolder.getUserAuth().getAdditionalInfo().get("MAIL"));
    assertEquals("another@example.com", authHolder.getUserAuth().getAdditionalInfo().get("mail"));
    AuthenticationHolderEntity saved = authHolderRepo.save(authHolder);
    assertEquals("mail@example.com", saved.getUserAuth().getAdditionalInfo().get("MAIL"));
    assertEquals("another@example.com", saved.getUserAuth().getAdditionalInfo().get("mail"));
  }
}
