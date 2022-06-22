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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.test.oauth.EndpointsTestUtils;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class JWKEndpointTests extends EndpointsTestUtils implements JWKTestSupport {

  @Value("${spring.web.resources.cache.cachecontrol.max-age}")
  private int maxAge;

  @Test
  public void jwkEndpointReturnsKeyMaterial() throws Exception {

    // @formatter:off
    mvc.perform(get(JWK_ENDPOINT))
    .andExpect(status().isOk())
    .andExpect(content().contentType(APPLICATION_JSON_VALUE))
    .andExpect(jsonPath("$.keys", hasSize(1)))
    .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
    .andExpect(jsonPath("$.keys[0].e").value("AQAB"))
    .andExpect(jsonPath("$.keys[0].kid").value("rsa1"))
    .andExpect(jsonPath("$.keys[0].n").value("4GRvJuFantVV3JdjwQOAkfREnwUFp2znRBTOIJhPamyH4gf4YlI5PQT79415NV4_HrWYzgooH5AK6-7WE-TLLGEAVK5vdk4vv79bG7ukvjvBPxAjEhQn6-Amln88iXtvicEGbh--3CKbQj1jryVU5aWM6jzweaabFSeCILVEd6ZT7ofXaAqan9eLzU5IEtTPy5MfrrOvWw5Q7D2yzMqc5LksmaQSw8XtmhA8gnENnIqjAMmPtRltf93wjtmiamgVENOVPdN-93Nd5w-pnMwEyoO6Q9JqXxV6lD6qBRxI7_5t4_vmVxcbbxcZbSAMoHqA2pbSMJ4Jcw-27Hct9jesLQ"))
    .andExpect(header().string("Cache-Control","max-age=" + maxAge +", must-revalidate, no-transform"));
    // @formatter:on

  }
}
