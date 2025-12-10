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
package it.infn.mw.iam.test.core;


import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.SavedUserAuthentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.core.IamTokenService;
import it.infn.mw.iam.test.api.tokens.TestTokensUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@SuppressWarnings("deprecation")
@ExtendWith(SpringExtension.class)
@IamMockMvcIntegrationTest
public class IamTokenServiceTests extends TestTokensUtils {

  public static final String TEST_CLIENT_ID = "client";
  public static final String TESTUSER_USERNAME = "test";

  @Autowired
  private IamTokenService tokenService;

  @Test
  void testPreAuthenticatedUserCannotGetToken() {
    SavedUserAuthentication savedAuth = new SavedUserAuthentication();
    savedAuth.setName(TESTUSER_USERNAME);
    savedAuth.setAuthenticated(true);
    savedAuth.setAuthorities(List.of(Authorities.ROLE_PRE_AUTHENTICATED));

    ClientDetailsEntity client = loadTestClient(TEST_CLIENT_ID);

    OAuth2Request req = new OAuth2Request(Map.of("grant_type", "authorization_code"),
        client.getClientId(), null, true, Set.of("openid"), null, null, null, null);

    OAuth2Authentication auth = new OAuth2Authentication(req, savedAuth);

    InvalidGrantException ex =
        assertThrows(InvalidGrantException.class, () -> tokenService.createAccessToken(auth));

    assertTrue(ex.getMessage().contains("User is not fully authenticated"));
  }
}
