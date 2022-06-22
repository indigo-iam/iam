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
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import it.infn.mw.iam.notification.NotificationProperties;
import it.infn.mw.iam.notification.service.resolver.AddressResolutionService;
import it.infn.mw.iam.notification.service.resolver.CompositeAdminsNotificationDelivery;
import it.infn.mw.iam.notification.service.resolver.NotifyAdminsStrategy;
import it.infn.mw.iam.notification.service.resolver.NotifyAdminAddressStrategy;

@RunWith(MockitoJUnitRunner.class)
public class CompositeNotificationPolicyTests extends AddressResolutionServiceTestSupport {

  public static final String ADMIN_ADDRESS = "admin.list@example";

  @Mock
  NotificationProperties props;

  @Mock
  AddressResolutionService ars;

  
  NotifyAdminsStrategy sta;
  NotifyAdminAddressStrategy stl;

  CompositeAdminsNotificationDelivery strategy;

  @Before
  public void before() {
    when(props.getAdminAddress()).thenReturn(ADMIN_ADDRESS);
    when(ars.resolveAddressesForAudience(VO_ADMINS))
      .thenReturn(asList(ADMIN_1_EMAIL, ADMIN_2_EMAIL));

    sta = new NotifyAdminsStrategy(ars);
    stl = new NotifyAdminAddressStrategy(props);
    strategy = new CompositeAdminsNotificationDelivery(asList(stl, sta));
  }
  
  @Test
  public void testComposite() {
    List<String> emails = strategy.resolveAdminEmailAddresses(); 
    
    assertThat(emails, hasSize(3));
    assertThat(emails, hasItem(ADMIN_ADDRESS));
    assertThat(emails, hasItem(ADMIN_1_EMAIL));
    assertThat(emails, hasItem(ADMIN_2_EMAIL));
  }
  
  
}
