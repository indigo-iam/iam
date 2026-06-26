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
package it.infn.mw.iam.test.startup;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;

import com.nimbusds.jwt.SignedJWT;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimConstants;
import it.infn.mw.iam.api.scim.model.ScimIndigoUser.INDIGO_USER_SCHEMA;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.TokenGetterUtils;
import it.infn.mw.iam.test.util.oauth.SecurityContextUtils;

@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class},
    properties = {"iam.dashboard.enabled=true", "iam.dashboard.client-id=dashboard-client",
        "iam.dashboard.client-secret=abcdefghijklmnopqrstuvwxyz123456",
        "scim.include_authorities=false", "iam.access_token.include_scope=false",
        "iam.access_token.store_on_database=true"})
@AutoConfigureMockMvc
public class DashboardIntegrationTests extends TokenGetterUtils {

  @Autowired
  SecurityContextUtils context;

  @BeforeEach
  void setup() {
    context.cleanupSecurityContext();
  }

  @Test
  void testScimMeEndpointReturnsAuthoritiesIfDashboardIsEnabled() throws Exception {

    context.useLocalTestUser();
    mvc.perform(get("/scim/Me").contentType(ScimConstants.SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$." + INDIGO_USER_SCHEMA.AUTHORITIES).exists());
  }

  @Test
  void testTokenContainsScopesIfDashboardIsEnabled() throws Exception {

    context.useLocalTestUser();
    String accessToken = getPasswordToken("profile email").accessToken();
    SignedJWT jwt = SignedJWT.parse(accessToken);
    assertNotNull(jwt.getJWTClaimsSet().getStringClaim("scope"));
  }
}
