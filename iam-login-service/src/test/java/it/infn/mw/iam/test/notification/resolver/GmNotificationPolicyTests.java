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

import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import it.infn.mw.iam.notification.service.resolver.AddressResolutionService;
import it.infn.mw.iam.notification.service.resolver.AdminNotificationDeliveryStrategy;
import it.infn.mw.iam.notification.service.resolver.NotifyGmStrategy;
import it.infn.mw.iam.notification.service.resolver.NotifyGmsAndAdminsStrategy;
import it.infn.mw.iam.persistence.model.IamGroup;

@RunWith(MockitoJUnitRunner.class)
public class GmNotificationPolicyTests extends AddressResolutionServiceTestSupport {

  public static final String ADMIN_ADDRESS = "admin.list@example";


  @Mock
  IamGroup group;

  @Mock
  AdminNotificationDeliveryStrategy ands;

  @Mock
  AddressResolutionService ars;

  @InjectMocks
  NotifyGmsAndAdminsStrategy strategy;
  
  @InjectMocks
  NotifyGmStrategy gmStrategy;

  @Before
  public void before() {
    when(ars.resolveAddressesForAudience("gm:001"))
      .thenReturn(asList(ADMIN_1_EMAIL, ADMIN_2_EMAIL));
    when(ands.resolveAdminEmailAddresses()).thenReturn((asList(ADMIN_ADDRESS)));

    when(group.getUuid()).thenReturn("001");
  }

  @Test
  public void testGmsAndAdmin() {

    assertThat(strategy.resolveGroupManagersEmailAddresses(group), hasSize(3));
    assertThat(strategy.resolveGroupManagersEmailAddresses(group), hasItem(ADMIN_ADDRESS));
    assertThat(strategy.resolveGroupManagersEmailAddresses(group), hasItem(ADMIN_1_EMAIL));
    assertThat(strategy.resolveGroupManagersEmailAddresses(group), hasItem(ADMIN_2_EMAIL));
  }
  
  @Test
  public void testGms() {

    assertThat(gmStrategy.resolveGroupManagersEmailAddresses(group), hasSize(2));
    assertThat(gmStrategy.resolveGroupManagersEmailAddresses(group), hasItem(ADMIN_1_EMAIL));
    assertThat(gmStrategy.resolveGroupManagersEmailAddresses(group), hasItem(ADMIN_2_EMAIL));
  }

}
