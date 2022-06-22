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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@TestPropertySource(properties = {"iam.jwk.keystore-location=classpath:/jwk/iam-1024-keys.jwks"})
public class JWKKeyTests1024 extends EndpointsTestUtils implements JWKTestSupport {


  @Test
  public void test1024bitsKeysAreSupported() throws Exception {
    // @formatter:off
    mvc.perform(get(JWK_ENDPOINT))
    .andExpect(status().isOk())
    .andExpect(content().contentType(APPLICATION_JSON_VALUE))
    .andExpect(jsonPath("$.keys", hasSize(1)))
    .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
    .andExpect(jsonPath("$.keys[0].e").value("AQAB"))
    .andExpect(jsonPath("$.keys[0].kid").value("rsa1"))
    .andExpect(jsonPath("$.keys[0].n").value("l081_MZpipySxN1mfZBepohm9N8xE6xozr41todbdUGOzb8Wy0lunrauXZ7u-jDBVz-dDid9yExbE491LR3FYhu-MrqpYreSebhnp6QxjlChlDQ6bGVR8aFXGTLYZUW3-YlunghmVSTnBCTWZyzJNoc4jJvQXAb7WLNKRNF55Fk"));
    // @formatter:on
  }

}
