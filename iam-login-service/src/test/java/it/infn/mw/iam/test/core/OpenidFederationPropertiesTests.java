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
package it.infn.mw.iam.test.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@ActiveProfiles({"h2-test", "dev", "openid-federation"})
@TestPropertySource(properties = {
  "openid-federation.entity-configuration.federation-entity.logo-uri=https://logo-example.com",
  "openid-federation.entity-configuration.federation-entity.organization-name=INDIGO IAM",
  "openid-federation.entity-configuration.federation-entity.contacts=iam-support@lists.infn.it"})
class OpenidFederationPropertiesTests {

  private String endpoint = "/.well-known/openid-federation";

  @Autowired
  private MockMvc mvc;

  @Test
  @SuppressWarnings("unchecked")
  void testFederationEntityPropertiesNotEmpty() throws Exception {

    MvcResult result = mvc.perform(get(endpoint))
      .andExpect(status().isOk())
      .andExpect(content().contentType("application/entity-statement+jwt"))
      .andReturn();

    String responseBody = result.getResponse().getContentAsString();
    assertThat(responseBody.split("\\.")).hasSize(3);

    SignedJWT jwt = SignedJWT.parse(responseBody);
    Map<String, Object> metadata = (Map<String, Object>) jwt.getJWTClaimsSet().getClaim("metadata");
    assertNotNull(metadata);

    Map<String, Object> federationEntity = (Map<String, Object>) metadata.get("federation_entity");
    assertNotNull(federationEntity);
    assertNotNull(federationEntity.get("organization_name"));
    assertNotNull(federationEntity.get("contacts"));
    assertNotNull(federationEntity.get("logo_uri"));
  }
}
