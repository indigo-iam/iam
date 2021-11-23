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
package it.infn.mw.iam.test.oauth.jwk;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.web.jwk.IamJWKSetPublishingEndpoint;
import it.infn.mw.iam.test.oauth.EndpointsTestUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = IamLoginService.class)
@WebAppConfiguration
@Transactional
public class JWKEndpointTests extends EndpointsTestUtils {

  private static final String ENDPOINT = "/" + IamJWKSetPublishingEndpoint.URL;

  @Before
  public void setup() throws Exception {
    buildMockMvc();
  }

  @Test
  public void testKeys() throws Exception {

    // @formatter:off
    mvc.perform(get(ENDPOINT))
    .andExpect(status().isOk())
    .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
    .andExpect(jsonPath("$.keys", hasSize(1)))
    .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
    .andExpect(jsonPath("$.keys[0].e").value("AQAB"))
    .andExpect(jsonPath("$.keys[0].kid").value("rsa1"))
    .andExpect(jsonPath("$.keys[0].n").value("nuvTJO-6RxIbIyYpPvAWeLSZ4o8o9T_lFU0ltiqAlp5eR-ID36aPqMvBGnNOcTVPcoFpfmQL5INgoWNJGTUm7pWTpV1wZjZe7PX6dFBhRe8SQQ0yb5SVc29-sX1QK-Cg7gKTe0l7Wrhve2vazHH1uYEqLUoTVnGsAx1nzL66M-M"));
    // @formatter:on

  }
}
