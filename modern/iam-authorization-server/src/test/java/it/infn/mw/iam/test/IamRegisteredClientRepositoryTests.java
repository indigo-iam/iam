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
package it.infn.mw.iam.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import it.infn.mw.iam.core.IamClientMapper;
import it.infn.mw.iam.core.IamRegisteredClientRepository;
import it.infn.mw.iam.persistence.client.model.ClientDetailsEntity;
import it.infn.mw.iam.persistence.client.repository.IamClientRepository;

@ExtendWith(MockitoExtension.class)
class IamRegisteredClientRepositoryTests {

  @Mock
  private IamClientRepository repository;

  @Mock
  private IamClientMapper mapper;

  private IamRegisteredClientRepository registeredClientRepository;

  @BeforeEach
  void setUp() {
    registeredClientRepository = new IamRegisteredClientRepository(repository, mapper);
  }

  @Test
  void shouldFindRegisteredClientById() {
    ClientDetailsEntity client = new ClientDetailsEntity();
    client.setId(123L);
    RegisteredClient registeredClient = RegisteredClient.withId("123")
      .clientId("test-client")
      .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
      .build();
    when(repository.findById(123L)).thenReturn(Optional.of(client));
    when(mapper.toRegisteredClient(client)).thenReturn(registeredClient);
    RegisteredClient result = registeredClientRepository.findById("123");
    assertEquals(registeredClient, result);
    verify(repository).findById(123L);
    verify(mapper).toRegisteredClient(client);
  }

  @Test
  void shouldReturnNullWhenClientIdIsNotFound() {
    when(repository.findById(123L)).thenReturn(Optional.empty());
    RegisteredClient result = registeredClientRepository.findById("123");
    assertNull(result);
    verify(repository).findById(123L);
    verifyNoInteractions(mapper);
  }

  @Test
  void shouldFindRegisteredClientByClientId() {
    ClientDetailsEntity client = new ClientDetailsEntity();
    client.setClientId("test-client");
    RegisteredClient registeredClient = RegisteredClient.withId("123")
      .clientId("test-client")
      .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
      .build();
    when(repository.findByClientId("test-client")).thenReturn(Optional.of(client));
    when(mapper.toRegisteredClient(client)).thenReturn(registeredClient);
    RegisteredClient result = registeredClientRepository.findByClientId("test-client");
    assertEquals(registeredClient, result);
    verify(repository).findByClientId("test-client");
    verify(mapper).toRegisteredClient(client);
  }

  @Test
  void shouldReturnNullWhenClientIsNotFoundByClientId() {
    when(repository.findByClientId("test-client")).thenReturn(Optional.empty());
    RegisteredClient result = registeredClientRepository.findByClientId("test-client");
    assertNull(result);
    verify(repository).findByClientId("test-client");
    verifyNoInteractions(mapper);
  }
}
