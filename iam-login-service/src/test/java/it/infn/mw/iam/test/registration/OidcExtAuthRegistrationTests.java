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
package it.infn.mw.iam.test.registration;

import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.EXT_AUTH_ERROR_KEY;
import static it.infn.mw.iam.test.ext_authn.oidc.OidcTestConfig.TEST_OIDC_CLIENT_ID;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.registration.PersistentUUIDTokenGenerator;
import it.infn.mw.iam.registration.RegistrationRequestDto;
import it.infn.mw.iam.test.ext_authn.oidc.FullyMockedOidcClientConfiguration;
import it.infn.mw.iam.test.ext_authn.oidc.OidcTestConfig;
import it.infn.mw.iam.test.util.WithMockOIDCUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oidc.MockOIDCProvider;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class, OidcTestConfig.class,
    FullyMockedOidcClientConfiguration.class}, webEnvironment = WebEnvironment.MOCK)
public class OidcExtAuthRegistrationTests {

  @Autowired
  private MockOIDCProvider oidcProvider;

  @Autowired
  private IamAccountRepository iamAccountRepo;

  @Autowired
  private ObjectMapper objectMapper;

  @Autowired
  private PersistentUUIDTokenGenerator generator;

  @Autowired
  private MockMvc mvc;

  private static final String TEST_100_USER = "test_100";

  private Authentication anonymousAuthenticationToken() {
    return new AnonymousAuthenticationToken("key", "anonymous",
        AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
  }

  @Test
  @WithMockOIDCUser(subject = TEST_100_USER, issuer = OidcTestConfig.TEST_OIDC_ISSUER)
  public void externalOidcRegistrationCreatesDisabledAccount() throws Exception {

    // Given a registration request linked to an external authn token has been submitted

    String username = "test-oidc-subject";

    String email = username + "@example.org";
    RegistrationRequestDto request = new RegistrationRequestDto();
    request.setGivenname("Test");
    request.setFamilyname("User");
    request.setEmail(email);
    request.setUsername(username);
    request.setNotes("Some short notes...");

    byte[] requestBytes = mvc
      .perform(post("/registration/create").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsBytes(request)))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsByteArray();

    request = objectMapper.readValue(requestBytes, RegistrationRequestDto.class);
    String token = generator.getLastToken();

    // If the user tries to authenticate with his external account, he's redirected to the
    // login page with an account disabled error

    MockHttpSession session =
        (MockHttpSession) mvc
          .perform(get("/openid_connect_login").with(
              SecurityMockMvcRequestPostProcessors.authentication(anonymousAuthenticationToken())))
          .andExpect(status().isFound())
          .andExpect(MockMvcResultMatchers
            .redirectedUrlPattern(OidcTestConfig.TEST_OIDC_AUTHORIZATION_ENDPOINT_URI + "**"))
          .andReturn()
          .getRequest()
          .getSession();

    String state = (String) session.getAttribute("state");
    String nonce = (String) session.getAttribute("nonce");

    oidcProvider.prepareTokenResponse(TEST_OIDC_CLIENT_ID, TEST_100_USER, nonce);

    session =
        (MockHttpSession) mvc
          .perform(get("/openid_connect_login").param("state", state)
            .param("code", "1234")
            .session(session))
          .andExpect(status().isFound())
          .andExpect(MockMvcResultMatchers.redirectedUrlPattern("/login**"))
          .andExpect(
              MockMvcResultMatchers.request().sessionAttribute(EXT_AUTH_ERROR_KEY, notNullValue()))
          .andReturn()
          .getRequest()
          .getSession();

    assertThat(session.getAttribute(EXT_AUTH_ERROR_KEY), instanceOf(DisabledException.class));

    DisabledException err = (DisabledException) session.getAttribute(EXT_AUTH_ERROR_KEY);
    assertThat(err.getMessage(),
        startsWith("Your registration request to indigo-dc was submitted successfully"));

    // the same happens after having confirmed the request
    mvc.perform(get("/registration/confirm/{token}", token)).andExpect(status().isOk());

    session =
        (MockHttpSession) mvc
          .perform(get("/openid_connect_login").with(
              SecurityMockMvcRequestPostProcessors.authentication(anonymousAuthenticationToken())))
          .andExpect(status().isFound())
          .andExpect(MockMvcResultMatchers
            .redirectedUrlPattern(OidcTestConfig.TEST_OIDC_AUTHORIZATION_ENDPOINT_URI + "**"))
          .andReturn()
          .getRequest()
          .getSession();

    state = (String) session.getAttribute("state");
    nonce = (String) session.getAttribute("nonce");

    oidcProvider.prepareTokenResponse(TEST_OIDC_CLIENT_ID, TEST_100_USER, nonce);

    session =
        (MockHttpSession) mvc
          .perform(get("/openid_connect_login").param("state", state)
            .param("code", "1234")
            .session(session))
          .andExpect(status().isFound())
          .andExpect(MockMvcResultMatchers.redirectedUrlPattern("/login**"))
          .andExpect(request().sessionAttribute(EXT_AUTH_ERROR_KEY, notNullValue()))
          .andReturn()
          .getRequest()
          .getSession();

    assertThat(session.getAttribute(EXT_AUTH_ERROR_KEY), instanceOf(DisabledException.class));
    err = (DisabledException) session.getAttribute(EXT_AUTH_ERROR_KEY);
    assertThat(err.getMessage(), startsWith(
        "Your registration request to indigo-dc was submitted and confirmed successfully"));

    IamAccount account = iamAccountRepo.findByOidcId(OidcTestConfig.TEST_OIDC_ISSUER, TEST_100_USER)
      .orElseThrow(() -> new AssertionError("Expected account not found"));

    iamAccountRepo.delete(account);
  }
}
