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

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import it.infn.mw.iam.core.oauth.consent.DefaultConsentExemptionService;
import it.infn.mw.iam.core.oauth.consent.ConsentExemptionService;
import it.infn.mw.iam.persistence.model.ConsentExemption;
import it.infn.mw.iam.persistence.repository.IamConsentExemptionRepository;

@ExtendWith(MockitoExtension.class)
class DefaultConsentExemptionServiceTests {

  @Mock
  private IamConsentExemptionRepository repository;

  private ConsentExemptionService service;

  @BeforeEach
  void setUp() {
    service = new DefaultConsentExemptionService(repository);
  }

  @Test
  void findAllReturnsRepositoryResults() {
    List<ConsentExemption> expected = List.of(
        site(
            1L,
            "client-one",
            "admin-user",
            Set.of("openid", "profile")
        ),
        site(
            2L,
            "client-two",
            "admin-user",
            Set.of("openid")
        )
    );

    when(repository.findAll()).thenReturn(expected);

    List<ConsentExemption> result = service.findAll();

    assertSame(expected, result);
    verify(repository).findAll();
  }

  @Test
  void findByIdReturnsEntityWhenItExists() {
    ConsentExemption expected = site(
        10L,
        "test-client",
        "admin-user",
        Set.of("openid", "profile")
    );

    when(repository.findById(10L))
        .thenReturn(Optional.of(expected));

    Optional<ConsentExemption> result = service.findById(10L);

    assertTrue(result.isPresent());
    assertSame(expected, result.orElseThrow());

    verify(repository).findById(10L);
  }

  @Test
  void findByIdReturnsEmptyWhenEntityDoesNotExist() {
    when(repository.findById(999L))
        .thenReturn(Optional.empty());

    Optional<ConsentExemption> result = service.findById(999L);

    assertTrue(result.isEmpty());
    verify(repository).findById(999L);
  }

  @Test
  void removeDeletesEntity() {
    ConsentExemption entity = site(
        3L,
        "client-to-delete",
        "admin-user",
        Set.of("openid")
    );

    service.remove(entity);

    verify(repository).delete(entity);
  }

  @Test
  void saveReturnsSavedEntity() {
    ConsentExemption input = site(
        null,
        "new-client",
        "admin-user",
        Set.of("openid", "email")
    );

    ConsentExemption saved = site(
        15L,
        "new-client",
        "admin-user",
        Set.of("openid", "email")
    );

    when(repository.save(input)).thenReturn(saved);

    ConsentExemption result = service.save(input);

    assertSame(saved, result);
    verify(repository).save(input);
  }

  @Test
  void findByClientIdReturnsEntityWhenItExists() {
    String clientId = "known-client";

    ConsentExemption expected = site(
        7L,
        clientId,
        "admin-user",
        Set.of("openid", "profile")
    );

    when(repository.findByClientId(clientId))
        .thenReturn(Optional.of(expected));

    Optional<ConsentExemption> result =
        service.findByClientId(clientId);

    assertTrue(result.isPresent());
    assertSame(expected, result.orElseThrow());

    verify(repository).findByClientId(clientId);
  }

  @Test
  void findByClientIdReturnsEmptyWhenClientDoesNotExist() {
    String clientId = "unknown-client";

    when(repository.findByClientId(clientId))
        .thenReturn(Optional.empty());

    Optional<ConsentExemption> result =
        service.findByClientId(clientId);

    assertTrue(result.isEmpty());
    verify(repository).findByClientId(clientId);
  }

  private static ConsentExemption site(
      Long id,
      String clientId,
      String creatorUserId,
      Set<String> allowedScopes
  ) {
    ConsentExemption site = new ConsentExemption();
    site.setId(id);
    site.setClientId(clientId);
    site.setCreatorUserId(creatorUserId);
    site.setAllowedScopes(allowedScopes);
    return site;
  }
}
