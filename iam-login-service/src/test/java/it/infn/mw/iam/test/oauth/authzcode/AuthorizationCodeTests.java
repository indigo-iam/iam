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
package it.infn.mw.iam.test.oauth.authzcode;

import static java.lang.String.format;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.securityContext;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.util.Date;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class AuthorizationCodeTests {

  public static final String TEST_CLIENT_ID = "client";
  public static final String TEST_CLIENT_SECRET = "secret";
  public static final String TEST_CLIENT_REDIRECT_URI =
      "https://iam.local.io/iam-test-client/openid_connect_login";

  public static final String LOGIN_URL = "http://localhost/login";

  public static final String AUTHORIZE_URL = "http://localhost/authorize";
  public static final String SIGN_AUP_URL = "/iam/aup/sign";
  public static final String SIGN_AUP_URL_EXTENDED = "http://localhost/iam/aup/sign";

  public static final String RESPONSE_TYPE_CODE = "code";

  public static final String SCOPE = "openid profile";

  public static final String TEST_USER_ID = "test";
  public static final String TEST_USER_PASSWORD = "password";

  @Autowired
  private IamAupRepository aupRepo;

  @Value("${iam.baseUrl}")
  private String iamBaseUrl;

  @Autowired
  private MockMvc mvc;

  @Test
  public void testOidcAuthorizationCodeFlowExternalHint() throws Exception {

    UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(AUTHORIZE_URL)
      .queryParam("response_type", RESPONSE_TYPE_CODE)
      .queryParam("client_id", TEST_CLIENT_ID)
      .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .queryParam("scope", SCOPE)
      .queryParam("nonce", "1")
      .queryParam("state", "1")
      .queryParam("ext_authn_hint", "saml:exampleId")
      .build();

    String authzEndpointUrl = uriComponents.toUriString();

    mvc.perform(get(authzEndpointUrl))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl(format("%s/saml/login?idp=exampleId", iamBaseUrl)));
  }

  @Test
  public void testOidcAuthorizationCodeFlow() throws Exception {

    UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(AUTHORIZE_URL)
      .queryParam("response_type", RESPONSE_TYPE_CODE)
      .queryParam("client_id", TEST_CLIENT_ID)
      .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .queryParam("scope", SCOPE)
      .queryParam("nonce", "1")
      .queryParam("state", "1")
      .build();

    String authzEndpointUrl = uriComponents.toUriString();

    MockHttpSession session = (MockHttpSession) mvc.perform(get(authzEndpointUrl))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl(LOGIN_URL))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(LOGIN_URL).param("username", TEST_USER_ID)
        .param("password", TEST_USER_PASSWORD)
        .param("submit", "Login")
        .session(session))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl(uriComponents.encode().toUriString()))
      .andReturn()
      .getRequest()
      .getSession();

  }

  @Test
  public void testOidcAuthorizationCodeFlowWithAUPSignature() throws Exception {

    IamAup aup = new IamAup();

    aup.setCreationTime(new Date());
    aup.setLastUpdateTime(new Date());
    aup.setName("default-aup");
    aup.setUrl("http://default-aup.org/");
    aup.setDescription("AUP description");
    aup.setSignatureValidityInDays(0L);

    aupRepo.save(aup);

    UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(AUTHORIZE_URL)
      .queryParam("response_type", RESPONSE_TYPE_CODE)
      .queryParam("client_id", TEST_CLIENT_ID)
      .queryParam("redirect_uri", TEST_CLIENT_REDIRECT_URI)
      .queryParam("scope", SCOPE)
      .queryParam("nonce", "1")
      .queryParam("state", "1")
      .build();

    String authzEndpointUrl = uriComponents.toUriString();

    MockHttpSession session = (MockHttpSession) mvc.perform(get(authzEndpointUrl))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl(LOGIN_URL))
      .andReturn()
      .getRequest()
      .getSession();

    session = (MockHttpSession) mvc
      .perform(post(LOGIN_URL).session(session)
        .param("username", TEST_USER_ID)
        .param("password", TEST_USER_PASSWORD)
        .param("submit", "Login"))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl(SIGN_AUP_URL))
      .andReturn()
      .getRequest()
      .getSession();

    SecurityContext context = (SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT");


    session = (MockHttpSession) mvc
      // Not sure why I have to do this, since using session *should be* enough
      .perform(get(SIGN_AUP_URL).session(session).with(securityContext(context)))
      .andExpect(status().isOk())
      .andExpect(view().name("iam/signAup"))
      .andReturn()
      .getRequest()
      .getSession();


    mvc.perform(post(SIGN_AUP_URL).session(session).with(securityContext(context)))
      .andExpect(status().isFound())
      .andExpect(redirectedUrl(uriComponents.encode().toUriString()))
      .andReturn()
      .getRequest()
      .getSession();

  }

}
