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
package it.infn.mw.iam.test.oauth.consent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.ZoneId;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.openid.connect.model.ApprovedSite;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import it.infn.mw.iam.core.oauth.consent.IamApprovedSiteService;
import it.infn.mw.iam.persistence.repository.IamApprovedSiteRepository;

class IamApprovedSiteServiceTests {

  @Mock
  private IamApprovedSiteRepository siteRepository;

  @Mock
  private ClientDetailsEntity client;

  private Clock clock;

  private IamApprovedSiteService service;

  @BeforeEach
  void setup() {

    MockitoAnnotations.openMocks(this);
    clock = Clock.fixed(Clock.systemUTC().instant(), ZoneId.of("UTC"));
    service = new IamApprovedSiteService(clock, siteRepository);
  }

  @Test
  void testCreateApprovedSite() {
    Set<String> scopes = Set.of("read", "write");
    Date timeout = new Date();

    ApprovedSite saved = new ApprovedSite();

    when(siteRepository.saveAndFlush(any())).thenReturn(saved);
    when(client.getClientId()).thenReturn("client1");

    ApprovedSite result = service.createApprovedSite(client, "user1", timeout, scopes);

    assertNotNull(result);

    ArgumentCaptor<ApprovedSite> captor = ArgumentCaptor.forClass(ApprovedSite.class);
    verify(siteRepository).saveAndFlush(captor.capture());

    ApprovedSite created = captor.getValue();

    assertEquals("client1", created.getClient().getClientId());
    assertEquals("user1", created.getUserId());
    assertEquals(timeout, created.getTimeoutDate());
    assertEquals(scopes, created.getAllowedScopes());

    Date expectedNow = Date.from(clock.instant());
    assertEquals(expectedNow, created.getCreationDate());
    assertEquals(expectedNow, created.getAccessDate());
  }

  @Test
  void testGetAll() {
    List<ApprovedSite> sites = List.of(new ApprovedSite());
    when(siteRepository.findAll()).thenReturn(sites);

    Collection<ApprovedSite> result = service.getAll();

    assertEquals(sites, result);
  }

  @Test
  void testGetById_found() {
    ApprovedSite site = new ApprovedSite();
    when(siteRepository.findById(1L)).thenReturn(Optional.of(site));

    ApprovedSite result = service.getById(1L).orElseThrow();

    assertEquals(site, result);
  }

  @Test
  void testGetById_notFound() {

    when(siteRepository.findById(1L)).thenReturn(Optional.empty());
    assertTrue(service.getById(1L).isEmpty());
  }

  @Test
  void testRemove() {

    ApprovedSite site = new ApprovedSite();
    service.remove(site);
    verify(siteRepository).delete(site);
  }

  @Test
  void testClearApprovedSitesForClient() {

    ApprovedSite site1 = new ApprovedSite();
    ApprovedSite site2 = new ApprovedSite();

    when(siteRepository.findByClient_ClientId("client1")).thenReturn(List.of(site1, site2));

    service.clearApprovedSitesForClient("client1");

    verify(siteRepository).delete(site1);
    verify(siteRepository).delete(site2);
  }
}
