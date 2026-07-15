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
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import it.infn.mw.iam.core.oauth.consent.IamConsentGrantService;
import it.infn.mw.iam.persistence.model.ConsentGrant;
import it.infn.mw.iam.persistence.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.repository.IamConsentGrantRepository;

class IamConsentGrantServiceTests {

  @Mock
  private IamConsentGrantRepository repository;

  @Mock
  private ClientDetailsEntity client;

  private Clock clock;

  private IamConsentGrantService service;

  @BeforeEach
  void setup() {

    MockitoAnnotations.openMocks(this);
    clock = Clock.fixed(Clock.systemUTC().instant(), ZoneId.of("UTC"));
    service = new IamConsentGrantService(clock, repository);
  }

  @Test
  void testCreateConsentGrant() {
    Set<String> scopes = Set.of("read", "write");
    Date timeout = new Date();

    ConsentGrant saved = new ConsentGrant();

    when(repository.saveAndFlush(any())).thenReturn(saved);
    when(client.getClientId()).thenReturn("client1");

    ConsentGrant result = service.createConsentGrant(client, "user1", timeout, scopes);

    assertNotNull(result);

    ArgumentCaptor<ConsentGrant> captor = ArgumentCaptor.forClass(ConsentGrant.class);
    verify(repository).saveAndFlush(captor.capture());

    ConsentGrant created = captor.getValue();

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
    List<ConsentGrant> sites = List.of(new ConsentGrant());
    when(repository.findAll()).thenReturn(sites);

    Collection<ConsentGrant> result = service.getAll();

    assertEquals(sites, result);
  }

  @Test
  void testGetById_found() {
    ConsentGrant site = new ConsentGrant();
    when(repository.findById(1L)).thenReturn(Optional.of(site));

    ConsentGrant result = service.getById(1L).orElseThrow();

    assertEquals(site, result);
  }

  @Test
  void testGetById_notFound() {

    when(repository.findById(1L)).thenReturn(Optional.empty());
    assertTrue(service.getById(1L).isEmpty());
  }

  @Test
  void testRemove() {

    ConsentGrant site = new ConsentGrant();
    service.remove(site);
    verify(repository).delete(site);
  }
}
