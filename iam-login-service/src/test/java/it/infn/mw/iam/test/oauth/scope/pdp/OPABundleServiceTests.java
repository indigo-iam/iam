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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;
import java.util.zip.GZIPInputStream;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.scim.converter.DefaultScimResourceLocationProvider;
import it.infn.mw.iam.api.scope_policy.DefaultScopePolicyConverter;
import it.infn.mw.iam.api.scope_policy.OPABundleService;
import it.infn.mw.iam.api.scope_policy.ScopePolicyService;
import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;
import it.infn.mw.iam.test.repository.ScopePolicyTestUtils;

@ExtendWith(MockitoExtension.class)
class OPABundleServiceTests extends ScopePolicyTestUtils {
  
  @Mock
  private ScopePolicyService policyService;
  
  @Mock
  private IamAccountRepository accountRepository;

  @Mock
  private IamGroupRepository groupRepository;

  private final ObjectMapper objectMapper = new ObjectMapper();

  private OPABundleService opaBundleService;

  @BeforeEach
  void setup() {
    DefaultScopePolicyConverter converter = new DefaultScopePolicyConverter(
      new DefaultScimResourceLocationProvider(), accountRepository, groupRepository);

    opaBundleService = new OPABundleService(policyService, converter, objectMapper);
  }

  @Test
  void testBundleContainsAllPolicies() throws IOException {
    when(policyService.findAllScopePolicies())
      .thenReturn(List.of(initPolicy("Policy 1"), initPolicy("Policy 2"), initPolicy("Policy 3")));
      
    JsonNode policies = readPolicies(opaBundleService.buildBundle().content());

    assertEquals(3, policies.size());
    assertEquals("Policy 1", policies.get(0).get("description").asText());
    assertEquals("Policy 2", policies.get(1).get("description").asText());
    assertEquals("Policy 3", policies.get(2).get("description").asText());
  }

  // Create a policy
  private IamScopePolicy initPolicy(String description) {
    IamScopePolicy policy = initPermitScopePolicy();
    policy.setDescription(description);
    return policy;
  }

  // Reverse process for gzip conversion in OPABundleService
  // It opens the gzip file, then the tar file, and searches for data.json, returning the `policies` array
  private JsonNode readPolicies(byte[] bundle) throws IOException {
    try (TarArchiveInputStream tar =
      new TarArchiveInputStream(new GZIPInputStream(new ByteArrayInputStream(bundle)))
    ) {
      TarArchiveEntry entry;
      while ((entry = tar.getNextEntry()) != null) {
        if ("data.json".equals(entry.getName())) {
          return objectMapper.readTree(tar.readAllBytes()).get("policies");
        }
      }
    }

    throw new AssertionError("data.json not found in the bundle");
  }

  @Test
  void testETagDoesNotChangeWhenPoliciesAreUnchanged() throws IOException {
    when(policyService.findAllScopePolicies())
      .thenReturn(List.of(initPolicy("Policy 1"), initPolicy("Policy 2"), initPolicy("Policy 3")));
    
    String firstETag = opaBundleService.buildBundle().etag();
    String secondETag = opaBundleService.buildBundle().etag();

    assertEquals(firstETag, secondETag);
  }

  @Test
  void testETagChangesWhenPolicyIsModified() throws IOException {
    IamScopePolicy policy = initPolicy("Policy 2");

    when(policyService.findAllScopePolicies())
      .thenReturn(List.of(initPolicy("Policy 1"), policy, initPolicy("Policy 3")));
    
    String firstETag = opaBundleService.buildBundle().etag();
    policy.setDescription("Policy 2 modified");
    String secondETag = opaBundleService.buildBundle().etag();

    assertNotEquals(firstETag, secondETag);
  }
}
