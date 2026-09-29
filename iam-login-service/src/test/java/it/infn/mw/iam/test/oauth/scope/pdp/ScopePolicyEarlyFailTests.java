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
package it.infn.mw.iam.test.oauth.scope.pdp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.google.common.collect.Sets;

import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamScopePolicyRepository;
import it.infn.mw.iam.test.repository.ScopePolicyTestUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@SuppressWarnings("deprecation")
@ExtendWith(SpringExtension.class)
@TestPropertySource(properties = {"iam.scope-authz.early-fail=true"})
@IamMockMvcIntegrationTest
class ScopePolicyEarlyFailTests extends ScopePolicyTestUtils {

  @Autowired
  IamScopePolicyRepository policyScopeRepo;

  @Autowired
  IamAccountRepository accountRepo;

  @Autowired
  ScopeFilter pdp;

  @Test
  void testEarlyFailWhenScopeIsNotAllowed() {

    IamAccount testAccount = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test account not found!"));

    IamScopePolicy up = initDenyScopePolicy();
    up.linkAccount(testAccount);
    up.getScopes().add(PROFILE);
    policyScopeRepo.save(up);

    Set<String> requestedScopes = Sets.newHashSet(OPENID, PROFILE, SCIM_WRITE);

    InvalidRequestException exception = assertThrows(InvalidRequestException.class,
        () -> pdp.filterScopes(requestedScopes, testAccount, CLIENT_ID));
    assertEquals("Scopes not allowed by the scope policy", exception.getMessage());

    policyScopeRepo.delete(up);
  }

  @Test
  void tesScopesAreAllowed() {

    IamAccount testAccount = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test account not found!"));

    IamScopePolicy up = initDenyScopePolicy();
    up.linkAccount(testAccount);
    up.getScopes().add(WHATEVER);
    policyScopeRepo.save(up);

    Set<String> requestedScopes = Sets.newHashSet(OPENID, PROFILE);
    Set<String> filteredScopes = pdp.filterScopes(requestedScopes, testAccount, CLIENT_ID);

    assertEquals(requestedScopes, filteredScopes);

    policyScopeRepo.delete(up);
  }
}
