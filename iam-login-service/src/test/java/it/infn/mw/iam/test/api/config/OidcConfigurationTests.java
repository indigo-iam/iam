/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2018
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
package it.infn.mw.iam.test.api.config;

import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.config.oidc.OidcProvider;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = {IamLoginService.class})
@WebAppConfiguration
@Transactional
//@formatter:off
@TestPropertySource(properties = {
    "oidc.providers[0].name=google",
    "oidc.providers[0].issuer=https://accounts.google.com",
    "oidc.providers[0].client.clientId=define_me_please",
    "oidc.providers[0].client.clientSecret=define_me_please",
    "oidc.providers[0].client.redirectUris=https://iam.local.io/openid_connect_login",
    "oidc.providers[0].client.scope=openid,profile,email,address,phone",
    "oidc.providers[0].loginButton.order=0",
    "oidc.providers[0].loginButton.text=Sign-in with Google",
    "oidc.providers[0].loginButton.style=google", 
    "oidc.providers[1].name=oidc-01",
    "oidc.providers[1].issuer=http://oidc-01.test",
    "oidc.providers[1].client.clientId=oidc-01-client-id",
    "oidc.providers[1].client.clientSecret=oidc-01-client-secret",
    "oidc.providers[1].client.redirectUris=http://iam.local.io/openid_connect_login",
    "oidc.providers[1].client.scope=openid,profile,email,address,phone",
    "oidc.providers[1].loginButton.order=1",
    "oidc.providers[1].loginButton.text=Sign-in with OIDC-01",
    "oidc.providers[1].loginButton.style=openid", 
    "oidc.providers[2].name=oidc-02",
    "oidc.providers[2].issuer=http://oidc-02.test",
    "oidc.providers[2].client.clientId=oidc-02-client-id",
    "oidc.providers[2].client.clientSecret=oidc-02-client-secret",
    "oidc.providers[2].client.redirectUris=https://iam.local.io/openid_connect_login",
    "oidc.providers[2].client.scope=openid,profile,email,address,phone",
    "oidc.providers[2].loginButton.order=2",
    "oidc.providers[2].loginButton.text=Sign-in with OIDC-02",
    "oidc.providers[2].loginButton.style=openid",
    "oidc.providers[3].name=empty",
    "oidc.providers[3].issuer=",
    "oidc.providers[3].client.clientId=",
    "oidc.providers[3].client.clientSecret=",
    "oidc.providers[3].client.redirectUris=",
    "oidc.providers[3].client.scope=",
    "oidc.providers[3].loginButton.order=",
    "oidc.providers[3].loginButton.text=Sign-in with Empty",
    "oidc.providers[3].loginButton.style=openid",
    })
  //@formatter:on}
public class OidcConfigurationTests {

  private static final String ENDPOINT = "/iam/config/oidc/providers";

  @Autowired
  private WebApplicationContext context;

  @Autowired
  private ObjectMapper mapper;

  private MockMvc mvc;

  @Before
  public void setup() {
    mvc = MockMvcBuilders.webAppContextSetup(context)
      .apply(springSecurity())
      .alwaysDo(print())
      .build();

    MockitoAnnotations.initMocks(this);
  }

  @Test
  public void testGetConfiguredProviders() throws Exception {

    // @formatter:off
    String response = mvc.perform(get((ENDPOINT)))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();
    // @formatter:on

    List<OidcProvider> providers =
        mapper.readValue(response, new TypeReference<List<OidcProvider>>() {});

    assertThat(providers, not(empty()));
    assertThat(providers, hasSize(2));

    for (OidcProvider oidc : providers) {
      assertThat(oidc.getClient(), nullValue());
    }

    assertThat(providers.get(0).getName(), equalTo("oidc-01"));
    assertThat(providers.get(0).getIssuer(), equalTo("http://oidc-01.test"));
    assertThat(providers.get(0).getLoginButton(), notNullValue());
    assertThat(providers.get(0).getLoginButton().getText(), equalTo("Sign-in with OIDC-01"));
    assertThat(providers.get(0).getLoginButton().getStyle(), equalTo("openid"));

    assertThat(providers.get(1).getName(), equalTo("oidc-02"));
    assertThat(providers.get(1).getIssuer(), equalTo("http://oidc-02.test"));
    assertThat(providers.get(1).getLoginButton(), notNullValue());
    assertThat(providers.get(1).getLoginButton().getText(), equalTo("Sign-in with OIDC-02"));
    assertThat(providers.get(1).getLoginButton().getStyle(), equalTo("openid"));
  }
}
