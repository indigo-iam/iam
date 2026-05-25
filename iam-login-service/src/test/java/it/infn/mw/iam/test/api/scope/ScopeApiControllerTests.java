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
package it.infn.mw.iam.test.api.scope;

import static org.junit.jupiter.api.Assertions.fail;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mitre.oauth2.model.SystemScope;
import org.mitre.oauth2.service.SystemScopeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scope.SystemScopeDto;
import it.infn.mw.iam.core.oauth.scope.IamSystemScopeService;
import it.infn.mw.iam.persistence.repository.IamScopeRepository;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
class ScopeApiControllerTests {

  @Autowired
  MockMvc mockMvc;

  @Autowired
  IamScopeRepository scopeRepository;

  @Autowired
  SystemScopeService scopeService;

  @Autowired
  ObjectMapper objectMapper;

  @Test
  @WithMockUser(roles = "USER")
  void getAllScopesReturnScopes() throws Exception {

    long expectedCount = scopeRepository.count();

    mockMvc.perform(get("/api/scopes"))
      .andExpect(status().isOk())
      .andExpect(content().contentType(MediaType.APPLICATION_JSON))
      .andExpect(jsonPath("$.length()").value(expectedCount));
  }

  @Test
  @WithMockUser(roles = "USER")
  void getByIdShouldReturnScope() throws Exception {

    Optional<SystemScope> openidScope = scopeRepository.findByValue("openid");
    Assertions.assertTrue(openidScope.isPresent());
    long id = openidScope.get().getId();

    mockMvc.perform(get("/api/scopes/" + id))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.id").value(id))
      .andExpect(jsonPath("$.value").value("openid"));
  }

  @Test
  @WithMockUser(roles = "USER")
  void getByIdReturns404WhenScopeNotFound() throws Exception {

    mockMvc.perform(get("/api/scopes/10000")).andExpect(status().isNotFound());
  }

  @Test
  @WithMockUser(roles = "ADMIN")
  void createScope() throws Exception {

    SystemScopeDto dto = SystemScopeDto.builder().value("scope.read").build();

    mockMvc
      .perform(post("/api/scopes").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(dto)))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.value").value("scope.read"));
  }

  @Test
  @WithMockUser(roles = "ADMIN")
  void createStructuredScope() throws Exception {

    SystemScopeDto dto = SystemScopeDto.builder().value("prefix:/").structured(true).build();

    mockMvc
      .perform(post("/api/scopes").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(dto)))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.value").value("prefix:/"))
      .andExpect(jsonPath("$.structured").value(true));
  }

  @Test
  @WithMockUser(roles = "USER")
  void createScopeShouldReturn403WhenUserIsNotAdmin() throws Exception {

    SystemScopeDto dto = SystemScopeDto.builder().value("scope.read").build();

    mockMvc
      .perform(post("/api/scopes").contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(dto)))
      .andExpect(status().isForbidden());
  }

  @Test
  @WithMockUser(roles = "ADMIN")
  void createScopeShouldReturn400WhenValueIsReserved() {

    Set
      .of(IamSystemScopeService.REGISTRATION_TOKEN_SCOPE,
          IamSystemScopeService.RESOURCE_TOKEN_SCOPE)
      .stream()
      .forEach(reservedScope -> {

        SystemScopeDto dto = SystemScopeDto.builder().value(reservedScope).build();

        try {
          mockMvc
            .perform(post("/api/scopes").contentType(MediaType.APPLICATION_JSON)
              .content(objectMapper.writeValueAsString(dto)))
            .andExpect(status().isBadRequest());
        } catch (Exception e) {
          fail("Exception was not expected: " + e.getMessage());
        }
      });
  }

  @Test
  @WithMockUser(roles = "ADMIN")
  void updateScope() throws Exception {

    SystemScope newScope = new SystemScope();
    newScope.setValue("updated-scope");
    newScope.setDefaultScope(false);
    newScope.setRestricted(false);
    newScope.setStructured(false);
    SystemScope addedScope = scopeService.create(newScope);

    SystemScopeDto dto = SystemScopeDto.builder()
      .id(addedScope.getId() + 10) // id should be ignored
      .value(addedScope.getValue() + "-updated")
      .description("Brand new description")
      .defaultScope(true)
      .restricted(true)
      .build();

    mockMvc
      .perform(put("/api/scopes/" + addedScope.getId()).contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsString(dto)))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.id").value(addedScope.getId()))
      .andExpect(jsonPath("$.value").value(dto.getValue()));
  }

  @Test
  @WithMockUser(roles = "ADMIN")
  void deleteShouldRemoveScope() throws Exception {

    SystemScope newScope = new SystemScope();
    newScope.setValue("deleted-scope");
    newScope.setDefaultScope(false);
    newScope.setRestricted(false);
    newScope.setStructured(false);
    SystemScope addedScope = scopeService.create(newScope);

    mockMvc.perform(delete("/api/scopes/" + addedScope.getId())).andExpect(status().isOk());

    Assertions.assertTrue(scopeService.getById(addedScope.getId()).isEmpty());

    mockMvc.perform(delete("/api/scopes/" + addedScope.getId())).andExpect(status().isOk());
  }

  @Test
  void getAllScopesShouldReturn401WhenUnauthenticated() throws Exception {

    mockMvc.perform(get("/api/scopes")).andExpect(status().isUnauthorized());
  }


}
