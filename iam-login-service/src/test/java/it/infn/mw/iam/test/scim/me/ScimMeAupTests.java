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
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Clock;
import java.util.Date;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.aup.model.AupConverter;
import it.infn.mw.iam.api.aup.model.AupDTO;
import it.infn.mw.iam.api.scim.model.ScimIndigoUser;
import it.infn.mw.iam.test.api.aup.AupTestSupport;
import it.infn.mw.iam.test.scim.ScimRestUtilsMvc;

@SpringBootTest(classes = {IamLoginService.class, ScimRestUtilsMvc.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class ScimMeAupTests extends AupTestSupport {

  static final String ME_ENDPOINT = "/scim/Me";

  @Autowired
  AupConverter aupConverter;

  @Autowired
  MockMvc mvc;

  @Autowired
  Clock clock;

  @Test
  void meEndpointAupSignatureTests() throws Exception {

    mvc
      .perform(get(ME_ENDPOINT).with(user("admin").roles("USER", "ADMIN"))
        .contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(
          jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.AUP_SIGNATURE_TIME).doesNotExist());

    AupDTO aup = aupConverter.dtoFromEntity(buildDefaultAup(Date.from(clock.instant())));

    mvc
      .perform(post("/iam/aup").with(csrf().asHeader())
        .with(user("admin").roles("USER", "ADMIN"))
        .contentType(APPLICATION_JSON)
        .content(mapper.writeValueAsString(aup)))
      .andExpect(status().isCreated());

    mvc
      .perform(post("/iam/aup/signature").with(csrf().asHeader())
        .with(user("admin").roles("USER", "ADMIN")))
      .andExpect(status().isCreated());

    mvc
      .perform(get(ME_ENDPOINT).with(user("admin").roles("USER", "ADMIN"))
        .contentType(SCIM_CONTENT_TYPE))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$." + ScimIndigoUser.INDIGO_USER_SCHEMA.AUP_SIGNATURE_TIME).exists());

  }

}
