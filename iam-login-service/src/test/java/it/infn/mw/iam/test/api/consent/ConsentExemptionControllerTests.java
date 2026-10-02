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
package it.infn.mw.iam.test.api.consent;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.oauth.consent.ConsentExemptionService;
import it.infn.mw.iam.persistence.model.ConsentExemption;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
@WithMockUser(username = "test", roles = {"USER", "ADMIN"})
class ConsentExemptionControllerTests {

  @Autowired
  private MockMvc mockMvc;

  @MockBean
  private ConsentExemptionService exceptionService;

  @Test
  void getAllConsentExemptionsReturnsAllEntries() throws Exception {

    ConsentExemption first =
        exception(1L, "client-one", "creator-one", Set.of("openid", "profile"));
    ConsentExemption second = exception(2L, "client-two", "creator-two", Set.of("openid", "email"));

    when(exceptionService.findAll()).thenReturn(List.of(first, second));

    mockMvc.perform(get("/api/whitelist").accept(MediaType.APPLICATION_JSON))
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
      .andExpect(jsonPath("$", hasSize(2)))
      .andExpect(jsonPath("$[0].id", is(1)))
      .andExpect(jsonPath("$[0].clientId", is("client-one")))
      .andExpect(jsonPath("$[0].creatorUserId", is("creator-one")))
      .andExpect(jsonPath("$[0].allowedScopes", containsInAnyOrder("openid", "profile")))
      .andExpect(jsonPath("$[1].id", is(2)))
      .andExpect(jsonPath("$[1].clientId", is("client-two")))
      .andExpect(jsonPath("$[1].creatorUserId", is("creator-two")))
      .andExpect(jsonPath("$[1].allowedScopes", containsInAnyOrder("openid", "email")));

    verify(exceptionService).findAll();
  }

  @Test
  void getAllConsentExemptionsReturnsEmptyArrayWhenNoneExist() throws Exception {

    when(exceptionService.findAll()).thenReturn(List.of());

    mockMvc.perform(get("/api/whitelist").accept(MediaType.APPLICATION_JSON))
      .andExpect(status().isOk())
      .andExpect(content().json("[]"));

    verify(exceptionService).findAll();
  }

  @Test
  void getConsentExemptionReturnsExeptionWhenItExists() throws Exception {

    ConsentExemption entity =
        exception(10L, "test-client", "admin-user", Set.of("openid", "profile"));

    when(exceptionService.findById(10L)).thenReturn(Optional.of(entity));

    mockMvc.perform(get("/api/whitelist/{id}", 10L).accept(MediaType.APPLICATION_JSON))
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
      .andExpect(jsonPath("$.id", is(10)))
      .andExpect(jsonPath("$.clientId", is("test-client")))
      .andExpect(jsonPath("$.creatorUserId", is("admin-user")))
      .andExpect(jsonPath("$.allowedScopes", containsInAnyOrder("openid", "profile")));

    verify(exceptionService).findById(10L);
  }

  @Test
  void getConsentExemptionReturnsNotFoundWhenItDoesNotExist() throws Exception {

    when(exceptionService.findById(99L)).thenReturn(Optional.empty());

    mockMvc.perform(get("/api/whitelist/{id}", 99L).accept(MediaType.APPLICATION_JSON))
      .andExpect(status().isNotFound())
      .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
      .andExpect(jsonPath("$.error", is("Consent exemption with id 99 not found.")));

    verify(exceptionService).findById(99L);
  }

  @Test
  void addNewConsentExemptionSavesAndReturnsSite() throws Exception {

    Authentication authentication =
        new UsernamePasswordAuthenticationToken("authenticated-user", null);

    ConsentExemption saved =
        exception(25L, "new-client", "authenticated-user", Set.of("openid", "profile"));

    when(exceptionService.save(any(ConsentExemption.class))).thenReturn(saved);

    mockMvc
      .perform(post("/api/whitelist").principal(authentication)
        .contentType(MediaType.APPLICATION_JSON)
        .accept(MediaType.APPLICATION_JSON)
        .content("""
            {
              "clientId": "new-client",
              "allowedScopes": [
                "openid",
                "profile"
              ]
            }
            """))
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
      .andExpect(jsonPath("$.id", is(25)))
      .andExpect(jsonPath("$.clientId", is("new-client")))
      .andExpect(jsonPath("$.creatorUserId", is("authenticated-user")))
      .andExpect(jsonPath("$.allowedScopes", containsInAnyOrder("openid", "profile")));

    ArgumentCaptor<ConsentExemption> captor = ArgumentCaptor.forClass(ConsentExemption.class);

    verify(exceptionService).save(captor.capture());

    ConsentExemption submitted = captor.getValue();

    assertNull(submitted.getId());
    assertEquals("new-client", submitted.getClientId());
    assertEquals("test", submitted.getCreatorUserId());
    assertEquals(Set.of("openid", "profile"), submitted.getAllowedScopes());
  }

  @Test
  void addNewConsentExemptionUsesAuthenticatedPrincipalAsCreator() throws Exception {

    Authentication authentication =
        new UsernamePasswordAuthenticationToken("actual-authenticated-user", null);

    ConsentExemption saved =
        exception(30L, "client-id", "actual-authenticated-user", Set.of("openid"));

    when(exceptionService.save(any(ConsentExemption.class))).thenReturn(saved);

    mockMvc
      .perform(post("/api/whitelist").principal(authentication)
        .contentType(MediaType.APPLICATION_JSON)
        .accept(MediaType.APPLICATION_JSON)
        .content("""
            {
              "clientId": "client-id",
              "creatorUserId": "forged-user",
              "allowedScopes": ["openid"]
            }
            """))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.creatorUserId", is("actual-authenticated-user")));

    ArgumentCaptor<ConsentExemption> captor = ArgumentCaptor.forClass(ConsentExemption.class);

    verify(exceptionService).save(captor.capture());

    assertEquals("test", captor.getValue().getCreatorUserId());
  }

  @Test
  void deleteConsentExemptionRemovesSiteWhenItExists() throws Exception {

    ConsentExemption entity = exception(5L, "client-to-delete", "admin-user", Set.of("openid"));

    when(exceptionService.findById(5L)).thenReturn(Optional.of(entity));

    mockMvc.perform(delete("/api/whitelist/{id}", 5L))
      .andExpect(status().isNoContent())
      .andExpect(content().string(""));

    verify(exceptionService).findById(5L);
    verify(exceptionService).remove(entity);
  }

  @Test
  void deleteConsentExemptionReturnsNoContentWhenItDoesNotExist() throws Exception {

    when(exceptionService.findById(404L)).thenReturn(Optional.empty());

    mockMvc.perform(delete("/api/whitelist/{id}", 404L))
      .andExpect(status().isNoContent())
      .andExpect(content().string(""));

    verify(exceptionService).findById(404L);
    verify(exceptionService, never()).remove(any(ConsentExemption.class));
  }

  private static ConsentExemption exception(Long id, String clientId, String creatorUserId,
      Set<String> allowedScopes) {
    ConsentExemption e = new ConsentExemption();
    e.setId(id);
    e.setClientId(clientId);
    e.setCreatorUserId(creatorUserId);
    e.setAllowedScopes(allowedScopes);
    return e;
  }
}
