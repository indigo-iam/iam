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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import it.infn.mw.iam.config.IamProperties.OpaProperties;
import it.infn.mw.iam.core.oauth.scope.pdp.OpaRequest;
import it.infn.mw.iam.core.oauth.scope.pdp.OpaResponse;
import it.infn.mw.iam.core.oauth.scope.pdp.OpaScopePolicyEngine;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountGroupMembership;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.persistence.repository.IamScopePolicyRepository;
import it.infn.mw.iam.test.repository.ScopePolicyTestUtils;

@ExtendWith(MockitoExtension.class)
public class OPAScopePolicyEngineTests extends ScopePolicyTestUtils {

  @Mock
  private IamScopePolicyRepository policyRepo;

  @Mock
  private RestTemplateFactory restTemplateFactory;

  @Mock
  private RestTemplate restTemplate;

  @Mock
  private OpaProperties opaProperties;

  @Mock
  private IamAccount account;

  @Mock
  private IamGroup group;

  @Mock
  private IamAccountGroupMembership groupMembership;

  private OpaScopePolicyEngine engine;

  private OpaRequest request;

  private static final String OPA_URL = "http://opa:8181";

  @BeforeEach
  void setUp() {
    when(restTemplateFactory.newRestTemplate()).thenReturn(restTemplate);

    engine = new OpaScopePolicyEngine(policyRepo, restTemplateFactory, opaProperties);
    request = new OpaRequest(new OpaRequest.User("1234", Set.of("Analysis")),
        Set.of("openid", "profile", "email"));
  }

  @Test
  void testEvaluatePolicySuccess() {

    OpaResponse opaResponse = new OpaResponse(Set.of("email"), Set.of("openid", "profile"));

    when(opaProperties.getUrl()).thenReturn(OPA_URL);
    when(restTemplate.postForEntity(eq(OPA_URL), eq(request), eq(OpaResponse.class)))
      .thenReturn(new ResponseEntity<>(opaResponse, HttpStatus.OK));

    Optional<OpaResponse> result = engine.evaluatePolicy(request);

    assertEquals(opaResponse, result.get());
  }

  @Test
  void testEvaluatePolicySuccessWithEmptyResponse() {

    when(opaProperties.getUrl()).thenReturn(OPA_URL);
    when(restTemplate.postForEntity(eq(OPA_URL), eq(request), eq(OpaResponse.class)))
      .thenReturn(new ResponseEntity<>(null, HttpStatus.OK));

    Optional<OpaResponse> result = engine.evaluatePolicy(request);

    assertTrue(result.isEmpty());
  }

  @Test
  void testEvaluatePolicyWithServerError() {

    when(opaProperties.getUrl()).thenReturn(OPA_URL);
    when(restTemplate.postForEntity(eq(OPA_URL), eq(request), eq(OpaResponse.class)))
      .thenReturn(new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR));

    Optional<OpaResponse> result = engine.evaluatePolicy(request);

    assertTrue(result.isEmpty());
  }

  @Test
  void testEvaluatePolicyWithRestClientException() {

    when(opaProperties.getUrl()).thenReturn(OPA_URL);
    when(restTemplate.postForEntity(eq(OPA_URL), eq(request), eq(OpaResponse.class)))
      .thenThrow(new RestClientException("OPA unavailable"));

    Optional<OpaResponse> result = engine.evaluatePolicy(request);

    assertTrue(result.isEmpty());
  }

  @Test
  void testApplyOpaPolicyEngine() {

    Set<String> deniedScopes = Set.of("profile");
    Set<String> filteredScopes = Set.of("openid");
    OpaResponse opaResponse = new OpaResponse(deniedScopes, filteredScopes);

    when(opaProperties.getUrl()).thenReturn(OPA_URL);
    when(restTemplate.postForEntity(eq(OPA_URL), any(OpaRequest.class), eq(OpaResponse.class)))
      .thenReturn(new ResponseEntity<>(opaResponse, HttpStatus.OK));

    setupAccountGroupMembership(account, group, groupMembership);
    Set<String> requestedScopes = new HashSet<>(filteredScopes);
    requestedScopes.addAll(deniedScopes);

    assertEquals(filteredScopes, engine.apply(requestedScopes, account));
  }

  @Test
  void testApplyDefaultScopePolicyEngine() {

    when(opaProperties.getUrl()).thenReturn(OPA_URL);
    when(restTemplate.postForEntity(eq(OPA_URL), any(OpaRequest.class), eq(OpaResponse.class)))
      .thenReturn(new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR));

    setupAccountGroupMembership(account, group, groupMembership);
    IamScopePolicy up = initDenyScopePolicy();
    up.linkAccount(account);
    up.getScopes().add(OPENID);
    up.getScopes().add(PROFILE);
    when(account.getScopePolicies()).thenReturn(Set.of(up));

    assertEquals(Set.of(), engine.apply(Set.of("openid", "profile"), account));
  }

  private void setupAccountGroupMembership(IamAccount account, IamGroup group,
      IamAccountGroupMembership groupMembership) {

    when(account.getUuid()).thenReturn("1234");
    when(account.getGroups()).thenReturn(Set.of(groupMembership));
    when(group.getName()).thenReturn("Analysis");
    when(groupMembership.getGroup()).thenReturn(group);
  }

}
