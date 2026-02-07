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
package it.infn.mw.iam.test.scim.me;

import static it.infn.mw.iam.api.scim.model.ScimConstants.SCIM_CONTENT_TYPE;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.aup.model.AupConverter;
import it.infn.mw.iam.api.aup.model.AupDTO;
import it.infn.mw.iam.api.scim.model.ScimIndigoUser;
import it.infn.mw.iam.test.api.aup.AupTestSupport;
import it.infn.mw.iam.test.config.ClockConfig;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.scim.ScimRestUtilsMvc;
import it.infn.mw.iam.test.util.clock.MutableClock;
import it.infn.mw.iam.test.util.oauth.SecurityContextUtils;

@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class,
    ClockConfig.class, ScimRestUtilsMvc.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc(printOnlyOnFailure = true, print = MockMvcPrint.LOG_DEBUG)
@TestPropertySource(properties = {"spring.main.allow-bean-definition-overriding=true",})
@Transactional
class ScimMeAupTests extends AupTestSupport {

  static final String ME_ENDPOINT = "/scim/Me";

  @Autowired
  AupConverter aupConverter;

  @Autowired
  ObjectMapper mapper;

  @Autowired
  MockMvc mvc;

  @Autowired
  SecurityContextUtils context;

  @Autowired
  MutableClock clock;

  @BeforeEach
  void setup() {
    context.cleanupSecurityContext();
  }

  @Test
  @WithMockUser(username = "admin", roles = {"ADMIN", "USER"})
  void meEndpointAupSignatureTests() throws Exception {

    mvc.perform(get(ME_ENDPOINT).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(
          jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.AUP_SIGNATURE_TIME).doesNotExist());

    AupDTO aup = aupConverter.dtoFromEntity(buildDefaultAup(clock.now()));

    mvc
      .perform(
          post("/iam/aup").contentType(APPLICATION_JSON).content(mapper.writeValueAsString(aup)))
      .andExpect(status().isCreated());

    mvc.perform(post("/iam/aup/signature")).andExpect(status().isCreated());
    mvc.perform(get(ME_ENDPOINT).contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.AUP_SIGNATURE_TIME).exists());

  }

}
