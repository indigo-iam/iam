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
package it.infn.mw.iam.test.oauth.jwk;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class JWKEndpointTests extends EndpointsTestUtils implements JWKTestSupport {

  @Value("${spring.web.resources.cache.cachecontrol.max-age}")
  private int maxAge;

  @Test
  void jwkEndpointReturnsKeyMaterial() throws Exception {

    // @formatter:off
    mvc.perform(get(JWK_ENDPOINT))
    .andExpect(status().isOk())
    .andExpect(content().contentType(APPLICATION_JSON_VALUE))
    .andExpect(jsonPath("$.keys", hasSize(1)))
    .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
    .andExpect(jsonPath("$.keys[0].e").value("AQAB"))
    .andExpect(jsonPath("$.keys[0].kid").value("rsa1"))
    .andExpect(header().string("Cache-Control","max-age=" + maxAge +", must-revalidate, no-transform"));
    // @formatter:on
  }

}
