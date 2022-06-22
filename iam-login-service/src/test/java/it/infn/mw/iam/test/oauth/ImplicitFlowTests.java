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
package it.infn.mw.iam.test.oauth;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@SuppressWarnings("deprecation")
@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
// @WithAnonymousUser
public class ImplicitFlowTests {

  public static final String IMPLICIT_CLIENT_ID = "implicit-flow-client";
  public static final String IMPLICIT_CLIENT_REDIRECT_URL = "http://localhost:9876/implicit";

  public static final String LOGIN_URL = "http://localhost/login";
  public static final String AUTHORIZE_URL = "http://localhost/authorize";

  public static final String RESPONSE_TYPE_TOKEN_ID_TOKEN = "token id_token";

  public static final String SCOPE = "openid profile";

  public static final String TEST_USER_ID = "test";
  public static final String TEST_USER_PASSWORD = "password";

  @Autowired
  ObjectMapper objectMapper;

  @Autowired
  IamAupRepository aupRepo;

  @Autowired
  MockMvc mvc;

  @Test
  public void testImplicitFlowRedirectsToLoginUrlForAnonymousUser() throws Exception {

    UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(AUTHORIZE_URL)
      .queryParam("response_type", RESPONSE_TYPE_TOKEN_ID_TOKEN)
      .queryParam("client_id", IMPLICIT_CLIENT_ID)
      .queryParam("redirect_uri", IMPLICIT_CLIENT_REDIRECT_URL)
      .queryParam("scope", SCOPE)
      .queryParam("nonce", "1")
      .queryParam("state", "1")
      .build();

    String authzEndpointUrl = uriComponents.toUriString();

    mvc.perform(get(authzEndpointUrl))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl(LOGIN_URL))
      .andReturn()
      .getRequest()
      .getSession();
  }

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  public void testImplicitFlowRedirectsCorrectlyChecksRedirectUrl() throws Exception {

    UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(AUTHORIZE_URL)
      .queryParam("response_type", RESPONSE_TYPE_TOKEN_ID_TOKEN)
      .queryParam("client_id", IMPLICIT_CLIENT_ID)
      .queryParam("redirect_uri", "http://localhost:1234/implicit") // this is wrong on purpose
      .queryParam("scope", SCOPE)
      .queryParam("nonce", "1")
      .queryParam("state", "1")
      .build();

    String authzEndpointUrl = uriComponents.toUriString();

    mvc.perform(get(authzEndpointUrl))
      .andExpect(status().isBadRequest())
      .andExpect(view().name("forward:/oauth/error"))
      .andExpect(model().attributeExists("error"))
      .andExpect(model().attribute("error", instanceOf(RedirectMismatchException.class)));
  }
  
  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  public void testImplicitFlowSucceeds() throws Exception {

    UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(AUTHORIZE_URL)
      .queryParam("response_type", RESPONSE_TYPE_TOKEN_ID_TOKEN)
      .queryParam("client_id", IMPLICIT_CLIENT_ID)
      .queryParam("redirect_uri", IMPLICIT_CLIENT_REDIRECT_URL)
      .queryParam("scope", SCOPE)
      .queryParam("nonce", "1")
      .queryParam("state", "1")
      .build();

    String authzEndpointUrl = uriComponents.toUriString();

    MockHttpSession session =
        (MockHttpSession) mvc.perform(get(authzEndpointUrl))
          .andExpect(status().isOk())
          .andExpect(view().name("forward:/oauth/confirm_access"))
          .andReturn()
          .getRequest()
          .getSession();
    
   String redirectedUrl = mvc.perform(post("/authorize").with(csrf())
       .param("user_oauth_approval", "true")
       .param("scope_openid", "openid")
       .param("scope_profile", "profile")
       .param("authorize", "Authorize")
       .param("remember", "until-revoked")
       .session(session))
     .andExpect(status().is3xxRedirection())
     .andReturn().getResponse().getRedirectedUrl();
     
   assertThat(redirectedUrl, startsWith(IMPLICIT_CLIENT_REDIRECT_URL+"#"));
   assertThat(redirectedUrl, containsString("access_token="));
   assertThat(redirectedUrl, containsString("id_token="));
 
  }
}
