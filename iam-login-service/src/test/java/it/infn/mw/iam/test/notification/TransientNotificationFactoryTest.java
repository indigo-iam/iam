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
package it.infn.mw.iam.test.notification;

import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.beans.factory.annotation.Value;

import freemarker.template.Configuration;
import freemarker.template.Template;
import it.infn.mw.iam.core.IamNotificationType;
import it.infn.mw.iam.notification.NotificationProperties;
import it.infn.mw.iam.notification.TransientNotificationFactory;
import it.infn.mw.iam.notification.service.resolver.AdminNotificationDeliveryStrategy;
import it.infn.mw.iam.notification.service.resolver.GroupManagerNotificationDeliveryStrategy;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.model.IamUserInfo;

@RunWith(MockitoJUnitRunner.class)
public class TransientNotificationFactoryTest {
    @Mock
    Configuration fm;
    @Mock
    NotificationProperties np;
    @Mock
    AdminNotificationDeliveryStrategy ands;
    @Mock
    GroupManagerNotificationDeliveryStrategy gmds;
    @Mock
    Template template;
    @Mock
    IamAccount testUser;
    @Mock
    IamUserInfo testUserInfo;

    @Value("${iam.organisation.name}")
    private String organisationName;

    @InjectMocks
    TransientNotificationFactory transientNotificationFactory;

    @Before
    public void before() throws Exception {
        when(testUser.getUserInfo()).thenReturn(testUserInfo);
        when(testUserInfo.getName()).thenReturn("Test User");
        when(fm.getTemplate(anyString())).thenReturn(template);
    }

    @Test
    public void testCreateSetAsServiceAccountMessage() {
        IamEmailNotification iamEmailNotification = transientNotificationFactory
                .createSetAsServiceAccountMessage(testUser);

        assertTrue(iamEmailNotification.getSubject().contains("Account set as service account"));
        assertTrue(iamEmailNotification.getType().equals(IamNotificationType.SET_SERVICE_ACCOUNT));
    }

    @Test
    public void testCreateRevokeServiceAccountMessage() {
        IamEmailNotification iamEmailNotification = transientNotificationFactory
                .createRevokeServiceAccountMessage(testUser);
                
        assertTrue(iamEmailNotification.getSubject().contains("Account's service account status revoked"));
        assertTrue(iamEmailNotification.getType().equals(IamNotificationType.REVOKE_SERVICE_ACCOUNT));
    }
}
