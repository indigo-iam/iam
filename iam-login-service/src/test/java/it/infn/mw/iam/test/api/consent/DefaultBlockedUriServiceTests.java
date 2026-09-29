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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import it.infn.mw.iam.core.oauth.consent.BlockedUriService;
import it.infn.mw.iam.core.oauth.consent.DefaultBlockedUriService;
import it.infn.mw.iam.persistence.model.BlockedUri;
import it.infn.mw.iam.persistence.repository.IamBlockedUriRepository;

@ExtendWith(MockitoExtension.class)
class DefaultBlockedUriServiceTests {

  @Mock
  private IamBlockedUriRepository repository;

  private BlockedUriService service;

  @BeforeEach
  void setUp() {
    service = new DefaultBlockedUriService(repository);
  }

  @Test
  void findAllReturnsRepositoryResults() {
    List<BlockedUri> expected =
        List.of(site(1L, "https://blocked-one.example"), site(2L, "https://blocked-two.example"));

    when(repository.findAll()).thenReturn(expected);

    List<BlockedUri> result = service.findAll();

    assertSame(expected, result);
    verify(repository).findAll();
  }

  @Test
  void findByIdReturnsRepositoryResult() {
    BlockedUri expected = site(8L, "https://blocked.example");

    when(repository.findById(8L)).thenReturn(Optional.of(expected));

    Optional<BlockedUri> result = service.findById(8L);

    assertTrue(result.isPresent());
    assertSame(expected, result.orElseThrow());

    verify(repository).findById(8L);
  }

  @Test
  void findByIdReturnsEmptyWhenEntityDoesNotExist() {
    when(repository.findById(999L)).thenReturn(Optional.empty());

    Optional<BlockedUri> result = service.findById(999L);

    assertTrue(result.isEmpty());
    verify(repository).findById(999L);
  }

  @Test
  void removeDeletesEntity() {
    BlockedUri entity = site(3L, "https://blocked.example");

    service.remove(entity);

    verify(repository).delete(entity);
  }

  @Test
  void saveReturnsSavedEntity() {
    BlockedUri input = site(null, "https://blocked.example");

    BlockedUri saved = site(12L, "https://blocked.example");

    when(repository.save(input)).thenReturn(saved);

    BlockedUri result = service.save(input);

    assertSame(saved, result);
    verify(repository).save(input);
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {" ", "   ", "\t", "\n"})
  void isBlockedUriReturnsFalseForNullUri(String uri) {
    boolean result = service.isBlockedUri(uri);

    assertFalse(result);
    verify(repository, never()).findByUri(ArgumentMatchers.anyString());
  }

  @Test
  void isBlacklistedReturnsTrueWhenUriExists() {
    String uri = "https://blocked.example";

    when(repository.findByUri(uri)).thenReturn(Optional.of(site(1L, uri)));

    boolean result = service.isBlockedUri(uri);

    assertTrue(result);
    verify(repository).findByUri(uri);
  }

  @Test
  void isBlockedUriReturnsFalseWhenUriDoesNotExist() {
    String uri = "https://allowed.example";

    when(repository.findByUri(uri)).thenReturn(Optional.empty());

    boolean result = service.isBlockedUri(uri);

    assertFalse(result);
    verify(repository).findByUri(uri);
  }

  private static BlockedUri site(Long id, String uri) {
    BlockedUri site = new BlockedUri();
    site.setId(id);
    site.setUri(uri);
    return site;
  }
}
