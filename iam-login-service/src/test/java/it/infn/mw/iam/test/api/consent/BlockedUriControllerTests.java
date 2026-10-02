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

import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
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

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.core.oauth.consent.BlockedUriService;
import it.infn.mw.iam.persistence.model.BlockedUri;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Transactional
@WithMockUser(username = "test", roles = {"USER", "ADMIN"})
class BlockedUriControllerTests {

  @Autowired
  private MockMvc mockMvc;

  @MockBean
  private BlockedUriService blockedUriService;

  @Test
  void getAllBlockedUriReturnsAllSites() throws Exception {
    BlockedUri first = site(1L, "https://blocked-one.example");
    BlockedUri second = site(2L, "https://blocked-two.example");

    when(blockedUriService.findAll()).thenReturn(List.of(first, second));

    mockMvc.perform(get("/api/blacklist").accept(MediaType.APPLICATION_JSON))
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
      .andExpect(jsonPath("$", hasSize(2)))
      .andExpect(jsonPath("$[0].id", is(1)))
      .andExpect(jsonPath("$[0].uri", is("https://blocked-one.example")))
      .andExpect(jsonPath("$[1].id", is(2)))
      .andExpect(jsonPath("$[1].uri", is("https://blocked-two.example")));

    verify(blockedUriService).findAll();
  }

  @Test
  void getAllBlockedUriReturnsEmptyArrayWhenNoSitesExist() throws Exception {
    when(blockedUriService.findAll()).thenReturn(List.of());

    mockMvc.perform(get("/api/blacklist").accept(MediaType.APPLICATION_JSON))
      .andExpect(status().isOk())
      .andExpect(content().json("[]"));

    verify(blockedUriService).findAll();
  }

  @Test
  void getBlockedUriReturnsSiteWhenItExists() throws Exception {
    BlockedUri blockedUri = site(10L, "https://blocked.example");

    when(blockedUriService.findById(10L)).thenReturn(Optional.of(blockedUri));

    mockMvc.perform(get("/api/blacklist/{id}", 10L).accept(MediaType.APPLICATION_JSON))
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
      .andExpect(jsonPath("$.id", is(10)))
      .andExpect(jsonPath("$.uri", is("https://blocked.example")));

    verify(blockedUriService).findById(10L);
  }

  @Test
  void getBlockedUriReturnsNotFoundWhenSiteDoesNotExist() throws Exception {
    when(blockedUriService.findById(99L)).thenReturn(Optional.empty());

    mockMvc.perform(get("/api/blacklist/{id}", 99L).accept(MediaType.APPLICATION_JSON))
      .andExpect(status().isNotFound())
      .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
      .andExpect(jsonPath("$.error", is("Blocked URI with id 99 not found.")));

    verify(blockedUriService).findById(99L);
  }

  @Test
  void addNewBlockedUriSavesAndReturnsSite() throws Exception {
    BlockedUri saved = site(25L, "https://newly-blocked.example");

    when(blockedUriService.save(any(BlockedUri.class))).thenReturn(saved);

    mockMvc
      .perform(post("/api/blacklist").contentType(MediaType.APPLICATION_JSON)
        .accept(MediaType.APPLICATION_JSON)
        .content("""
            {
              "uri": "https://newly-blocked.example"
            }
            """))
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
      .andExpect(jsonPath("$.id", is(25)))
      .andExpect(jsonPath("$.uri", is("https://newly-blocked.example")));

    ArgumentCaptor<BlockedUri> captor = ArgumentCaptor.forClass(BlockedUri.class);

    verify(blockedUriService).save(captor.capture());

    BlockedUri submittedEntity = captor.getValue();

    assert submittedEntity.getId() == null;
    assert submittedEntity.getUri().equals("https://newly-blocked.example");
  }

  @Test
  void addNewBlockedUriIgnoresIdFromRequest() throws Exception {
    BlockedUri saved = site(100L, "https://blocked.example");

    when(blockedUriService.save(any(BlockedUri.class))).thenReturn(saved);

    mockMvc
      .perform(post("/api/blacklist").contentType(MediaType.APPLICATION_JSON)
        .accept(MediaType.APPLICATION_JSON)
        .content("""
            {
              "id": 999,
              "uri": "https://blocked.example"
            }
            """))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.id", is(100)))
      .andExpect(jsonPath("$.uri", is("https://blocked.example")));

    ArgumentCaptor<BlockedUri> captor = ArgumentCaptor.forClass(BlockedUri.class);

    verify(blockedUriService).save(captor.capture());

    BlockedUri submittedEntity = captor.getValue();

    assert submittedEntity.getId() == null;
  }

  @Test
  void deleteBlockedUriRemovesSiteWhenItExists() throws Exception {
    BlockedUri blockedUri = site(5L, "https://blocked.example");

    when(blockedUriService.findById(5L)).thenReturn(Optional.of(blockedUri));

    doNothing().when(blockedUriService).remove(blockedUri);

    mockMvc.perform(delete("/api/blacklist/{id}", 5L))
      .andExpect(status().isNoContent())
      .andExpect(content().string(""));

    verify(blockedUriService).findById(5L);
    verify(blockedUriService).remove(blockedUri);
  }

  @Test
  void deleteBlockedUriReturnsNoContentWhenSiteDoesNotExist() throws Exception {

    when(blockedUriService.findById(404L)).thenReturn(Optional.empty());

    mockMvc.perform(delete("/api/blacklist/{id}", 404L))
      .andExpect(status().isNoContent())
      .andExpect(content().string(""));

    verify(blockedUriService).findById(404L);
    verify(blockedUriService, never()).remove(any());
  }

  private static BlockedUri site(Long id, String uri) {
    BlockedUri site = new BlockedUri();
    site.setId(id);
    site.setUri(uri);
    return site;
  }
}
