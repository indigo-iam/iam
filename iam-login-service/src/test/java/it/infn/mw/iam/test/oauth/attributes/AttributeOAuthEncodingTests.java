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
package it.infn.mw.iam.test.oauth.attributes;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.function.Supplier;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAttribute;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@TestPropertySource(properties = {"iam.access_token.include_authn_info=true"})
public class AttributeOAuthEncodingTests extends EndpointsTestUtils {

  public static final String TEST_USER = "test";
  public static final String EXPECTED_USER_NOT_FOUND = "Expected user not found";

  public static final IamAttribute TEST_ATTR = IamAttribute.newInstance(TEST_USER, TEST_USER);

  @Autowired
  private IamAccountRepository repo;

  @Autowired
  private IamAccountService accountService;

  @Autowired
  private MockOAuth2Filter mockOAuth2Filter;

  private Supplier<AssertionError> assertionError(String message) {
    return () -> new AssertionError(message);
  }

  @Before
  public void setup() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void cleanupOAuthUser() {
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @Test
  public void attrsAreNotEncodedIfNotRequested() throws Exception {
    IamAccount testAccount =
        repo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));
    
    accountService.setAttribute(testAccount, TEST_ATTR);

    AccessTokenGetter tg = buildAccessTokenGetter();
    tg.scope("openid profile");

    JWT token = JWTParser.parse(tg.getAccessTokenValue());
    assertThat(token.getJWTClaimsSet().getJSONObjectClaim("attr"), nullValue());

  }

  @Test
  public void attrsAreEncodedWhenRequested() throws Exception {
    IamAccount testAccount =
        repo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    accountService.setAttribute(testAccount, TEST_ATTR);

    AccessTokenGetter tg = buildAccessTokenGetter();
    tg.scope("openid profile attr");

    JWT token = JWTParser.parse(tg.getAccessTokenValue());
    assertThat(token.getJWTClaimsSet().getJSONObjectClaim("attr"), notNullValue());
    assertThat(token.getJWTClaimsSet().getJSONObjectClaim("attr").get("test"), is("test"));
  }
}
