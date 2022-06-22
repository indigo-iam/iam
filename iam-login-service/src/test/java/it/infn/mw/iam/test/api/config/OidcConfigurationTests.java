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
package it.infn.mw.iam.test.api.config;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.test.util.WithAnonymousUser;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@WithAnonymousUser
//@formatter:off
@TestPropertySource(properties = {
    "oidc.providers[0].name=google",
    "oidc.providers[0].issuer=https://accounts.google.com",
    "oidc.providers[0].client.clientId=",
    "oidc.providers[0].client.clientSecret=",
    "oidc.providers[0].client.scope=openid,profile,email,address,phone",
    "oidc.providers[0].loginButton.text=Sign in with Google",
    "oidc.providers[0].loginButton.style=google", 
    "oidc.providers[1].name=oidc-01",
    "oidc.providers[1].issuer=http://oidc-01.test",
    "oidc.providers[1].client.clientId=oidc-01-client-id",
    "oidc.providers[1].client.clientSecret=oidc-01-client-secret",
    "oidc.providers[1].client.redirectUris=http://iam.local.io/openid_connect_login",
    "oidc.providers[1].client.scope=openid,profile,email,address,phone",
    "oidc.providers[1].loginButton.text=Sign-in with OIDC-01",
    "oidc.providers[1].loginButton.style=openid", 
    "oidc.providers[2].name=oidc-02",
    "oidc.providers[2].issuer=http://oidc-02.test",
    "oidc.providers[2].client.clientId=oidc-02-client-id",
    "oidc.providers[2].client.clientSecret=oidc-02-client-secret",
    "oidc.providers[2].client.redirectUris=https://iam.local.io/openid_connect_login",
    "oidc.providers[2].client.scope=openid,profile,email,address,phone",
    "oidc.providers[2].loginButton.text=Sign-in with OIDC-02",
    "oidc.providers[2].loginButton.style=other"
    })
  //@formatter:on}
public class OidcConfigurationTests {

  private static final String PRIVACY_POLICY_ENDPOINT = "/iam/config/privacy-policy";
  private static final String ENDPOINT = "/iam/config/oidc/providers";
  
  @Autowired
  private MockMvc mvc;

  @Test
  public void testGetConfiguredProviders() throws Exception {
    
    mvc.perform(get((ENDPOINT)))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$", hasSize(2)))
      .andExpect(jsonPath("$[0].client").doesNotExist())
      .andExpect(jsonPath("$[1].client").doesNotExist())
      .andExpect(jsonPath("$[0].name", is("oidc-01")))
      .andExpect(jsonPath("$[0].issuer", is("http://oidc-01.test")))
      .andExpect(jsonPath("$[0].loginButton").exists())
      .andExpect(jsonPath("$[0].loginButton.text", is("Sign-in with OIDC-01")))
      .andExpect(jsonPath("$[0].loginButton.style", is("openid")))
      .andExpect(jsonPath("$[1].name", is("oidc-02")))
      .andExpect(jsonPath("$[1].issuer", is("http://oidc-02.test")))
      .andExpect(jsonPath("$[1].loginButton").exists())
      .andExpect(jsonPath("$[1].loginButton.text", is("Sign-in with OIDC-02")))
      .andExpect(jsonPath("$[1].loginButton.style", is("other")));
  }
  
  @Test
  public void testNullPrivacyPolicy() throws Exception {
    
    mvc.perform(get((PRIVACY_POLICY_ENDPOINT)))
    .andExpect(status().isOk())
    .andExpect(jsonPath("$.url").isEmpty());
  }
}
