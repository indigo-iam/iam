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

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertNotNull;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.audit.IamAuditEventLogger;
import it.infn.mw.iam.audit.events.IamAuditApplicationEvent;
import it.infn.mw.iam.audit.events.client.ClientCreatedEvent;
import it.infn.mw.iam.audit.events.client.ClientRemovedEvent;
import it.infn.mw.iam.audit.events.client.ClientUpdatedEvent;
import it.infn.mw.iam.test.oauth.client_registration.ClientRegistrationTestSupport.ClientJsonStringBuilder;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
public class ClientEventTests {
  
  @Autowired
  private IamAuditEventLogger logger;

  @Autowired
  private MockMvc mvc;

  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  public void testClientCreation() throws Exception {
  
    String jsonInString = ClientJsonStringBuilder.builder().name("client").scopes("test").build();
  
    // @formatter:off
    mvc.perform(post("/iam/api/clients")
            .contentType(APPLICATION_JSON)
            .content(jsonInString))
          .andExpect(status().isCreated())
          .andExpect(content().contentType(APPLICATION_JSON))
          .andReturn()
          .getResponse()
          .getContentAsString();
    // @formatter:on
    
    IamAuditApplicationEvent event = logger.getLastEvent();
    assertThat(event, instanceOf(ClientCreatedEvent.class));
    assertNotNull(event.getMessage());
    assertThat(event.getMessage(),
        containsString("Client created"));
  }
  
  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  public void testClientUpdate() throws Exception {
  
    String newScope = ClientJsonStringBuilder.builder().scopes("test1").build();
    
    mvc.perform(put("/iam/api/clients/client")
            .contentType(APPLICATION_JSON)
            .content(newScope))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.scope", is("test1")));
    // @formatter:on
    
    IamAuditApplicationEvent event = logger.getLastEvent();
    assertThat(event, instanceOf(ClientUpdatedEvent.class));
    assertNotNull(event.getMessage());
    assertThat(event.getMessage(),
        containsString("Client updated"));
  }
  
  @Test
  @WithMockUser(username = "admin", roles = "ADMIN")
  public void testClientDelete() throws Exception {
    
    mvc.perform(delete("/iam/api/clients/client")
            .contentType(APPLICATION_JSON))
          .andExpect(status().isNoContent());
    // @formatter:on
    
    IamAuditApplicationEvent event = logger.getLastEvent();
    assertThat(event, instanceOf(ClientRemovedEvent.class));
    assertNotNull(event.getMessage());
    assertThat(event.getMessage(),
        containsString("Client removed"));
  }
}