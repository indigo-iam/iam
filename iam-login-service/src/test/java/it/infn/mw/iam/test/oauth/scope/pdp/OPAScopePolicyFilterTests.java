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
import org.springframework.security.core.Authentication;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.google.common.collect.Sets;

import it.infn.mw.iam.core.oauth.scope.pdp.ScopeFilter;
import it.infn.mw.iam.core.oauth.scope.pdp.ScopePolicyException;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@ExtendWith(SpringExtension.class)
@TestPropertySource(properties = {"iam.opa.enabled=true", "iam.opa.url=http://opa:8181"})
@IamMockMvcIntegrationTest
class OPAScopePolicyFilterTests {

  @Autowired
  ScopeFilter pdp;

  @Test
  void testOPAFilterForClientCredentials() {

    Set<String> requestedScopes = Sets.newHashSet("openid", "profile", "scim:read");

    ScopePolicyException exception = assertThrows(ScopePolicyException.class,
        () -> pdp.filterScopes(requestedScopes, (Authentication) null, "client"));

    assertEquals("Unable to contact OPA", exception.getMessage());
    assertEquals("server_error", exception.getOAuth2ErrorCode());
    assertEquals(500, exception.getHttpErrorCode());
  }
}
