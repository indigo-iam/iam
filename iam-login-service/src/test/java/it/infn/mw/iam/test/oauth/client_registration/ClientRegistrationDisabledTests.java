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
package it.infn.mw.iam.test.oauth.client_registration;

import static org.hamcrest.CoreMatchers.containsString;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK,
    properties = "client-registration.enable=false")
public class ClientRegistrationDisabledTests extends ClientRegistrationTestSupport {

  public static final String REGISTRATION_DISABLED_MSG = "Client registration is disabled";

  @Autowired
  private MockMvc mvc;

  @Test
  public void testClientRegistrationDisabled() throws Exception {
    String jsonInString = ClientJsonStringBuilder.builder().scopes("test").build();

    mvc.perform(post(REGISTER_ENDPOINT).contentType(APPLICATION_JSON).content(jsonInString))
      .andExpect(status().isBadRequest())
      .andExpect(content().contentType(APPLICATION_JSON))
      .andExpect(jsonPath("$.error", containsString(REGISTRATION_DISABLED_MSG)));

    mvc.perform(post(LEGACY_REGISTER_ENDPOINT).contentType(APPLICATION_JSON).content(jsonInString))
      .andExpect(status().isBadRequest())
      .andExpect(content().contentType(APPLICATION_JSON))
      .andExpect(jsonPath("$.error", containsString(REGISTRATION_DISABLED_MSG)));

    mvc
      .perform(
          put(REGISTER_ENDPOINT + "/client").contentType(APPLICATION_JSON).content(jsonInString))
      .andExpect(status().isBadRequest())
      .andExpect(content().contentType(APPLICATION_JSON))
      .andExpect(jsonPath("$.error", containsString(REGISTRATION_DISABLED_MSG)));

    mvc
      .perform(
          put(LEGACY_REGISTER_ENDPOINT + "/client").contentType(APPLICATION_JSON)
            .content(jsonInString))
      .andExpect(status().isBadRequest())
      .andExpect(content().contentType(APPLICATION_JSON))
      .andExpect(jsonPath("$.error", containsString(REGISTRATION_DISABLED_MSG)));

    mvc.perform(get(REGISTER_ENDPOINT + "/client"))
      .andExpect(status().isBadRequest())
      .andExpect(content().contentType(APPLICATION_JSON))
      .andExpect(jsonPath("$.error", containsString(REGISTRATION_DISABLED_MSG)));

    mvc.perform(get(LEGACY_REGISTER_ENDPOINT + "/client"))
      .andExpect(status().isBadRequest())
      .andExpect(content().contentType(APPLICATION_JSON))
      .andExpect(jsonPath("$.error", containsString(REGISTRATION_DISABLED_MSG)));


    mvc.perform(delete(LEGACY_REGISTER_ENDPOINT + "/client"))
      .andExpect(status().isBadRequest())
      .andExpect(content().contentType(APPLICATION_JSON))
      .andExpect(jsonPath("$.error", containsString(REGISTRATION_DISABLED_MSG)));
  }

}
