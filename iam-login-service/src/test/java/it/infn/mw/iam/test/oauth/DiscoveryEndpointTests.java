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
package it.infn.mw.iam.test.oauth;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasItem;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Arrays;
import java.util.Set;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.google.common.collect.Sets;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.web.IamDiscoveryEndpoint;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;


@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class DiscoveryEndpointTests {

  private String endpoint = "/" + IamDiscoveryEndpoint.OPENID_CONFIGURATION_URL;

  private Set<String> iamSupportedGrants = Sets.newLinkedHashSet(Arrays.asList("authorization_code",
      "implicit", "refresh_token", "client_credentials", "password",
      "urn:ietf:params:oauth:grant-type:jwt-bearer", "urn:ietf:params:oauth:grant_type:redelegate",
      "urn:ietf:params:oauth:grant-type:token-exchange",
      "urn:ietf:params:oauth:grant-type:device_code"));

  private static final String IAM_ORGANISATION_NAME_CLAIM = "organisation_name";
  private static final String IAM_GROUPS_CLAIM = "groups";
  private static final String IAM_EXTERNAL_AUTHN_CLAIM = "external_authn";

  @Autowired
  private MockMvc mvc;

  @Test
  public void testGrantTypesSupported() throws Exception {

    // @formatter:off
    mvc.perform(post(endpoint))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.grant_types_supported").isNotEmpty())
        .andExpect(jsonPath("$.grant_types_supported").isArray())
        .andExpect(jsonPath("$.grant_types_supported").value(containsInAnyOrder(iamSupportedGrants.toArray())));
    // @formatter:on
  }

  @Test
  public void testSupportedClaims() throws Exception {

    // @formatter:off
    mvc.perform(post(endpoint))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.claims_supported").isNotEmpty())
        .andExpect(jsonPath("$.claims_supported").isArray())
        .andExpect(jsonPath("$.claims_supported", hasItem(IAM_ORGANISATION_NAME_CLAIM)))
        .andExpect(jsonPath("$.claims_supported", hasItem(IAM_GROUPS_CLAIM)))
        .andExpect(jsonPath("$.claims_supported", hasItem(IAM_EXTERNAL_AUTHN_CLAIM)));
    // @formatter:on
  }

  @Test
  public void testDeviceCodeEndpoint() throws Exception {
    // @formatter:off
    mvc.perform(post(endpoint))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.device_authorization_endpoint", is("http://localhost:8080/devicecode")));
    // @formatter:on
  }

}
