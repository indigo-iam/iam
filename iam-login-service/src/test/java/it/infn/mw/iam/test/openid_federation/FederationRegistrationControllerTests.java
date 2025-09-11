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
package it.infn.mw.iam.test.openid_federation;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.oidc.TrustChainService;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@ActiveProfiles({"h2-test", "dev", "openid-federation"})
@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class FederationRegistrationControllerTests {

  @Autowired
  private MockMvc mvc;

  @MockBean
  TrustChainService trustChainService;

  TrustChain fakeChain;

  @Test
  public void testSuccessfullExplicitClientRegistration() throws Exception {
    fakeChain = TrustChainTestFactory.createRpToTaChain();
    EntityStatement rpEC = fakeChain.getLeafSelfStatement();
    String rpJwt = rpEC.getSignedStatement().serialize();

    when(trustChainService.validateFromEntityConfiguration(any())).thenReturn(fakeChain);

    mvc
      .perform(post("/openid-federation/client-registration")
        .contentType("application/entity-statement+jwt")
        .content(rpJwt))
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(content().contentType("application/explicit-registration-response+jwt"));
  }
}
