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

import static java.util.Collections.emptyList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;

import it.infn.mw.iam.api.scim.converter.DefaultScimResourceLocationProvider;
import it.infn.mw.iam.api.scope_policy.DefaultScopePolicyConverter;
import it.infn.mw.iam.api.scope_policy.DefaultScopePolicyService;
import it.infn.mw.iam.api.scope_policy.IamScopePolicyConverter;
import it.infn.mw.iam.api.scope_policy.ScopePolicyDTO;
import it.infn.mw.iam.audit.events.scope_policy.ScopePolicyCreatedEvent;
import it.infn.mw.iam.audit.events.scope_policy.ScopePolicyDeletedEvent;
import it.infn.mw.iam.audit.events.scope_policy.ScopePolicyUpdatedEvent;
import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.persistence.model.PolicyRule;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;
import it.infn.mw.iam.persistence.repository.IamScopePolicyRepository;
import it.infn.mw.iam.test.repository.ScopePolicyTestUtils;

@RunWith(MockitoJUnitRunner.class)
public class ScopePolicyAuditTests extends ScopePolicyTestUtils {

  @Mock
  private ApplicationEventPublisher eventPublisher;

  @Mock
  private IamScopePolicyRepository scopePolicyRepo;

  @Mock
  private IamAccountRepository accountRepo;

  @Mock
  private IamGroupRepository groupRepo;

  @Captor
  private ArgumentCaptor<ApplicationEvent> eventCaptor;

  private IamScopePolicyConverter converter;

  private DefaultScopePolicyService service;

  @Before
  public void init() {
    converter = new DefaultScopePolicyConverter(new DefaultScimResourceLocationProvider(),
        accountRepo, groupRepo);

    // when(scopePolicyRepo.findDefaultPolicies()).thenReturn(emptyList());
    when(scopePolicyRepo.findEquivalentPolicies(Mockito.any()))
      .thenReturn(emptyList());
    
    when(scopePolicyRepo.save(Mockito.any(IamScopePolicy.class))).thenAnswer(returnsFirstArg());
    
    service = new DefaultScopePolicyService(scopePolicyRepo, converter, eventPublisher);
  }

  @Test
  public void testCreatePolicyRaisesEvent() {
    ScopePolicyDTO dto = initDenyScopePolicyDTO();
    IamScopePolicy sp=service.createScopePolicy(dto);
    verify(eventPublisher).publishEvent(eventCaptor.capture());

    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(ScopePolicyCreatedEvent.class));
    
    ScopePolicyCreatedEvent e = (ScopePolicyCreatedEvent)event;
    assertThat(e.getPolicy(), equalTo(sp));
  }
  
  @Test
  public void testRemovePolicyRaisesEvent() {
    ScopePolicyDTO dto = initDenyScopePolicyDTO();
    dto.setId(1L);
    
    IamScopePolicy sp = initDenyScopePolicy();
    sp.setId(1L);
    sp.setRule(PolicyRule.DENY);
    
    when(scopePolicyRepo.findById(1L)).thenReturn(Optional.of(sp));
    
    service.deleteScopePolicyById(1L);
    verify(eventPublisher).publishEvent(eventCaptor.capture());

    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(ScopePolicyDeletedEvent.class));
    
    ScopePolicyDeletedEvent e = (ScopePolicyDeletedEvent)event;
    assertThat(e.getPolicy(), equalTo(sp));
  }
  
  @Test
  public void testUpdatePolicyRaisesEvent(){
    ScopePolicyDTO dto = initPermitScopePolicyDTO();
    dto.setId(1L);
    
    IamScopePolicy sp = initDenyScopePolicy();
    sp.setId(1L);
    sp.setRule(PolicyRule.DENY);
    
    when(scopePolicyRepo.findById(1L)).thenReturn(Optional.of(sp));
    
    service.updateScopePolicy(dto);
    verify(eventPublisher).publishEvent(eventCaptor.capture());
    
    ApplicationEvent event = eventCaptor.getValue();
    assertThat(event, instanceOf(ScopePolicyUpdatedEvent.class));
    
    ScopePolicyUpdatedEvent e = (ScopePolicyUpdatedEvent)event;
    assertThat(e.getPolicy(), equalTo(sp));
    
  }

}
