/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019
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
package it.infn.mw.iam.test.oauth.labels;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

import java.util.function.Supplier;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.transaction.annotation.Transactional;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.oauth.MockOAuth2Filter;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {IamLoginService.class, CoreControllerTestSupport.class})
@WebAppConfiguration
@Transactional
@TestPropertySource(properties = {"iam.token-enhancer.include-labels[0].label.name=test",
    "iam.token-enhancer.include-labels[0].label.prefix=iam",
    "iam.token-enhancer.include-labels[0].claim-name=test_label",})
public class LabelsOAuthEncodingTests extends EndpointsTestUtils {
  public static final String TEST_USER = "test";
  public static final String EXPECTED_USER_NOT_FOUND = "Expected user not found";

  public static final String CLAIM_NAME = "test_label";
  public static final String TEST_LABEL_PREFIX = "iam";
  public static final String TEST_LABEL_NAME = "test";
  public static final String TEST_LABEL_VALUE = "value";

  public static final IamLabel TEST_LABEL = IamLabel.builder()
    .prefix(TEST_LABEL_PREFIX)
    .value(TEST_LABEL_VALUE)
    .name(TEST_LABEL_NAME)
    .build();

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
    buildMockMvc();
    mockOAuth2Filter.cleanupSecurityContext();
  }

  @After
  public void cleanupOAuthUser() {
    mockOAuth2Filter.cleanupSecurityContext();
  }


  @Test
  public void labelsAreProperlyEncodedIfConfigurationAllows() throws Exception {
    IamAccount testAccount =
        repo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    accountService.setLabel(testAccount, TEST_LABEL);

    AccessTokenGetter tg = buildAccessTokenGetter();
    tg.scope("openid profile");

    JWT idToken = JWTParser
      .parse((String) tg.getTokenResponseObject().getAdditionalInformation().get("id_token"));

    assertThat(idToken.getJWTClaimsSet().getStringClaim(CLAIM_NAME), is(TEST_LABEL_VALUE));

  }

  @Test
  public void getTokenSucceedsForUserWithoutLabel() throws Exception {

    repo.findByUsername(TEST_USER).orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

    AccessTokenGetter tg = buildAccessTokenGetter();
    tg.scope("openid profile");

    JWT idToken = JWTParser
      .parse((String) tg.getTokenResponseObject().getAdditionalInformation().get("id_token"));

    assertThat(idToken.getJWTClaimsSet().getStringClaim(CLAIM_NAME), nullValue());

  }
}
