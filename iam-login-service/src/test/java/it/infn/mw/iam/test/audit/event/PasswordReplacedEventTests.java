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
package it.infn.mw.iam.test.audit.event;

import static it.infn.mw.iam.api.scim.model.ScimConstants.SCIM_CONTENT_TYPE;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.audit.IamAuditEventLogger;
import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;
import it.infn.mw.iam.audit.events.account.PasswordReplacedEvent;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
class PasswordReplacedEventTests {

  @Autowired
  private IamAuditEventLogger logger;

  @Autowired
  private MockMvc mvc;

  @Autowired
  private ObjectMapper objectMapper;

  @Autowired
  private IamAccountRepository accountRepo;

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  void testPasswordReplacedEvent() throws Exception {
    IamAccount account = accountRepo.findAccountByUsername("test");
    Map<String, Object> payload =
        Map.of("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:PatchOp"), "operations",
            List.of(Map.of("op", "replace", "value", Map.of("password", "LEAKME-PaTcHv1-99887"))));

    mvc.perform(patch("/scim/Users/{accountId}", account.getUuid()).contentType(SCIM_CONTENT_TYPE)
      .content(objectMapper.writeValueAsString(payload))).andExpect(status().isNoContent());

    IamAuditApplicationEvent event = logger.getLastEvent();
    assertThat(event, instanceOf(PasswordReplacedEvent.class));
    assertThat(event.getMessage(), not(containsString("LEAKME-PaTcHv1-99887")));
    assertEquals("Replaced password for user test", event.getMessage());
  }
}
