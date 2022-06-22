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
package it.infn.mw.iam.test.notification.resolver;

import static it.infn.mw.iam.notification.service.resolver.DefaultAddressResolutionService.VO_ADMINS;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import it.infn.mw.iam.notification.service.resolver.DefaultAddressResolutionService;
import it.infn.mw.iam.notification.service.resolver.InvalidAudience;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@RunWith(MockitoJUnitRunner.class)
public class AddressResolutionServiceTests extends AddressResolutionServiceTestSupport {

  @Mock
  IamAccountRepository repo;

  @InjectMocks
  DefaultAddressResolutionService service;
  
  @Captor
  ArgumentCaptor<String> resolvedAudience;

  @Before
  public void setup() {
    when(repo.findByAuthority(ROLE_ADMIN)).thenReturn(emptyList());
  }

  @Test
  public void testVoAdminsNoAdminsResolution() {

    assertThat(service.resolveAddressesForAudience(VO_ADMINS),
        empty());
  }

  @Test(expected=InvalidAudience.class)
  public void testUnknownAudience() {
    service.resolveAddressesForAudience(INVALID_AUDIENCE);
  }
  
  @Test(expected=NullPointerException.class)
  public void testNullAudience() {
    service.resolveAddressesForAudience(null);
  }

  @Test
  public void testVoAdminsEmailResolution() {
    when(repo.findByAuthority(ROLE_ADMIN)).thenReturn(
        asList(createAccount(ADMIN_1, ADMIN_1_EMAIL), createAccount(ADMIN_2, ADMIN_2_EMAIL)));
    
    assertThat(service.resolveAddressesForAudience(VO_ADMINS),
        hasSize(2));
    
    assertThat(service.resolveAddressesForAudience(VO_ADMINS),
        hasItem(ADMIN_1_EMAIL));
    
    assertThat(service.resolveAddressesForAudience(VO_ADMINS),
        hasItem(ADMIN_2_EMAIL));
  }

  @Test
  public void testNoGroupManagerResolution() {
    when(repo.findByAuthority(GROUP_ADMIN_001)).thenReturn(emptyList());
    
    assertThat(service.resolveAddressesForAudience("gm:001"),
        empty());
    
    verify(repo).findByAuthority(resolvedAudience.capture());
    assertThat(resolvedAudience.getValue(), is(GROUP_ADMIN_001));
    
  }

}
