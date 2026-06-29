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
package it.infn.mw.iam.test.api.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.client.management.LegacyClientDto;
import it.infn.mw.iam.api.client.management.LegacyClientsApiController;
import it.infn.mw.iam.persistence.repository.client.IamClientRepository;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;

@SpringBootTest(classes = {IamLoginService.class, CoreControllerTestSupport.class},
    webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
class LegacyClientsApiControllerTests {

  @Autowired
  private MockMvc mvc;

  @Autowired
  private IamClientRepository clientRepo;

  @Autowired
  private ObjectMapper mapper;

  @Test
  @WithMockUser(username = "test", roles = {"USER"})
  void getAllClientsWorksForUser() throws Exception {

    long totalResults = clientRepo.count();

    List<LegacyClientDto> clients =
        mapper.readValue(mvc.perform(get(LegacyClientsApiController.ENDPOINT))
          .andExpect(status().isOk())
          .andReturn()
          .getResponse()
          .getContentAsString(), new TypeReference<List<LegacyClientDto>>() {});

    assertEquals(totalResults, clients.size());
  }

}
