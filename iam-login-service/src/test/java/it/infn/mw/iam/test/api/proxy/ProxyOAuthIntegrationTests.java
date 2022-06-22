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
package it.infn.mw.iam.test.api.proxy;

import static java.lang.String.format;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.sql.Date;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.model.IamX509ProxyCertificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.test.rcauth.RCAuthTestSupport;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;
import it.infn.mw.iam.test.util.oidc.TokenResponse;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(
    classes = {IamLoginService.class, RCAuthTestSupport.class, ProxyCertificateClockConfig.class},
    webEnvironment = WebEnvironment.MOCK)
@TestPropertySource(properties = {"proxycert.enabled=true", "rcauth.enabled=true",
    "rcauth.client-id=" + RCAuthTestSupport.CLIENT_ID,
    "rcauth.client-secret=" + RCAuthTestSupport.CLIENT_SECRET,
    "rcauth.issuer=" + RCAuthTestSupport.ISSUER})
public class ProxyOAuthIntegrationTests extends ProxyCertificateTestSupport {

  @Autowired
  IamProperties iamProperties;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private ObjectMapper mapper;

  @Autowired
  private MockMvc mvc;

  private void linkProxyToTestAccount() throws Exception {
    IamAccount testAccount = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test account not found"));

    linkTest0CertificateToAccount(testAccount);
    IamX509Certificate cert = testAccount.getX509Certificates().iterator().next();
    IamX509ProxyCertificate proxyCert = new IamX509ProxyCertificate();

    proxyCert.setChain(generateTest0Proxy(NOW, ONE_YEAR_FROM_NOW));
    proxyCert.setExpirationTime(Date.from(ONE_YEAR_FROM_NOW));
    proxyCert.setCertificate(cert);
    cert.setProxy(proxyCert);

    accountRepo.save(testAccount);
  }

  @Test
  public void clientAuthReallyRequired() throws Exception {

    linkProxyToTestAccount();

    String clientId = "password-grant";
    String clientSecret = "secret";

    String responseString = mvc
      .perform(post("/token").with(httpBasic(clientId, clientSecret))
        .param("grant_type", "password")
        .param("username", "test")
        .param("password", "password")
        .param("scope", "openid proxy:generate"))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.scope", equalTo("openid proxy:generate")))
      .andReturn()
      .getResponse()
      .getContentAsString();

    TokenResponse tr = mapper.readValue(responseString, TokenResponse.class);

    mvc
      .perform(
          post("/iam/proxycert").header("Authorization", format("Bearer %s", tr.getAccessToken())))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error").value("unauthorized"))
      .andExpect(jsonPath("$.error_description").value("No client credentials found in request"));


    mvc
      .perform(post("/iam/proxycert").param("client_id", clientId)
        .param("client_secret", "wrongsecret")
        .header("Authorization", format("Bearer %s", tr.getAccessToken())))
      .andExpect(status().isUnauthorized())
      .andExpect(jsonPath("$.error").value("unauthorized"))
      .andExpect(jsonPath("$.error_description").value("Bad credentials"));

    mvc
      .perform(post("/iam/proxycert").param("client_id", clientId)
        .param("client_secret", clientSecret)
        .header("Authorization", format("Bearer %s", tr.getAccessToken())))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.not_after").exists())
      .andExpect(jsonPath("$.subject").exists())
      .andExpect(jsonPath("$.issuer").exists())
      .andExpect(jsonPath("$.identity", is(TEST_0_SUBJECT)))
      .andExpect(jsonPath("$.certificate_chain").exists());
  }
}
