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
package it.infn.mw.iam.test.api.scim.provisioning;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.junit4.SpringRunner;

import com.google.common.collect.Lists;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.api.scim.model.ScimPatchOperation;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.api.scim.provisioning.ScimUserProvisioning;
import it.infn.mw.iam.core.IamNotificationType;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamEmailNotification;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamEmailNotificationRepository;
import it.infn.mw.iam.test.api.TestSupport;
import it.infn.mw.iam.test.core.CoreControllerTestSupport;
import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
@SpringBootTest(classes = { IamLoginService.class,
        CoreControllerTestSupport.class }, webEnvironment = WebEnvironment.MOCK)
public class ScimUserProvisioningTest extends TestSupport {
    @Autowired
    private ScimUserProvisioning provider;
    @Autowired
    private IamAccountRepository iamAccountRepo;
    @Autowired
    private IamEmailNotificationRepository notificationRepo;

    @Test
    public void testEmailSentForSettingServiceAccount() {
        IamAccount testUser = iamAccountRepo.findByUsername(TEST_USER)
                .orElseThrow(() -> new AssertionError("Expected test user not found"));
        ScimUser user = ScimUser.builder().serviceAccount(true).build();

        List<ScimPatchOperation<ScimUser>> operations = Lists.newArrayList();
        operations.add(new ScimPatchOperation.Builder<ScimUser>().replace().value(user).build());
        provider.update(testUser.getUuid(), operations);

        List<IamEmailNotification> notifications = notificationRepo
                .findByNotificationType(IamNotificationType.SET_SERVICE_ACCOUNT);

        assertEquals(1, notifications.size());
        assertEquals("[indigo-dc IAM] Account set as service account", notifications.get(0).getSubject());
    }

    @Test
    public void testEmailSentForRevokingServiceAccount() {
        IamAccount testUser = iamAccountRepo.findByUsername(TEST_USER)
                .orElseThrow(() -> new AssertionError("Expected test user not found"));
        testUser.setServiceAccount(true);
        iamAccountRepo.save(testUser);
        ScimUser user = ScimUser.builder().serviceAccount(false).build();

        List<ScimPatchOperation<ScimUser>> operations = Lists.newArrayList();
        operations.add(new ScimPatchOperation.Builder<ScimUser>().replace().value(user).build());
        provider.update(testUser.getUuid(), operations);

        List<IamEmailNotification> notifications = notificationRepo
                .findByNotificationType(IamNotificationType.REVOKE_SERVICE_ACCOUNT);

        assertEquals(1, notifications.size());
        assertEquals("[indigo-dc IAM] Account's service account status revoked", notifications.get(0).getSubject());
    }

}
