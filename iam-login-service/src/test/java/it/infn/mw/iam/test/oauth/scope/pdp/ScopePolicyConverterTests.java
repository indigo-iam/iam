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
package it.infn.mw.iam.test.oauth.scope.pdp;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.lenient;

import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import com.google.common.collect.Sets;

import it.infn.mw.iam.api.scim.converter.DefaultScimResourceLocationProvider;
import it.infn.mw.iam.api.scim.converter.ScimResourceLocationProvider;
import it.infn.mw.iam.api.scope_policy.DefaultScopePolicyConverter;
import it.infn.mw.iam.api.scope_policy.GroupRefDTO;
import it.infn.mw.iam.api.scope_policy.IamAccountRefDTO;
import it.infn.mw.iam.api.scope_policy.InvalidScopePolicyError;
import it.infn.mw.iam.api.scope_policy.ScopePolicyDTO;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;

@ExtendWith(MockitoExtension.class)
class ScopePolicyConverterTests {

  private ScimResourceLocationProvider locationProvider = new DefaultScimResourceLocationProvider();

  @Mock
  private IamAccountRepository accountRepository;

  @Mock
  private IamGroupRepository groupRepository;

  private DefaultScopePolicyConverter converter;

  @BeforeEach
  void setup() {

    converter =
        new DefaultScopePolicyConverter(locationProvider, accountRepository, groupRepository);

    lenient().when(accountRepository.findByUuid(Mockito.anyString())).thenReturn(Optional.empty());
    lenient().when(groupRepository.findByUuid(Mockito.anyString())).thenReturn(Optional.empty());
  }

  @Test
  void testInvalidAccountIdTriggersException() {
    ScopePolicyDTO policyDTO = new ScopePolicyDTO();

    IamAccountRefDTO accountRef = new IamAccountRefDTO();
    accountRef.setUuid(UUID.randomUUID().toString());

    policyDTO.setAccount(accountRef);
    policyDTO.setScopes(Sets.newHashSet("s1"));
    policyDTO.setRule("DENY");

    InvalidScopePolicyError e =
        assertThrows(InvalidScopePolicyError.class, () -> converter.toModel(policyDTO));
    assertThat(e.getMessage(), startsWith("No account found"));
  }

  @Test
  void testInvalidGroupIdTriggersException() {
    ScopePolicyDTO policyDTO = new ScopePolicyDTO();

    GroupRefDTO groupRef = new GroupRefDTO();
    groupRef.setUuid(UUID.randomUUID().toString());

    policyDTO.setGroup(groupRef);
    policyDTO.setScopes(Sets.newHashSet("s1"));
    policyDTO.setRule("DENY");

    InvalidScopePolicyError e =
        assertThrows(InvalidScopePolicyError.class, () -> converter.toModel(policyDTO));
    assertThat(e.getMessage(), startsWith("No group found"));
  }

}
