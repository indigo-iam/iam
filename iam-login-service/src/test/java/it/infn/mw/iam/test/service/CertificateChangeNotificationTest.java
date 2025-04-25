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

package it.infn.mw.iam.test.service;


import java.time.Instant;
import java.util.List;
import java.util.function.Supplier;
import org.springframework.boot.test.context.SpringBootTest;

import org.junit.runner.RunWith;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;

import com.google.common.collect.Lists;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@SpringBootTest
@RunWith(SpringRunner.class)
public class CertificateChangeNotificationTest {

    public static final String TEST_0_EMAIL = "test0@test.example";
    public static final String TEST_1_EMAIL = "test1@test.example";
    public static final String TEST_EMAIL_SUBJECT = "Subject";
    public static final String TEST_EMAIL_BODY = "Body";

    public static final String IAM_MAIL_FROM = "iam@test.example";
    public static final String IAM_ADMIN_ADDRESS = "admin@test.example";



    @Autowired
    protected IamAccountRepository accountRepo;


    public static final String TEST = "test";
    public static final String EXPECTED_USER_NOT_FOUND = "Expected user not found";
    public static final String TEST_0_SUBJECT = "CN=test0,O=IGI,C=IT";
    public static final String TEST_0_ISSUER = "CN=IGI TEST CA,O=IGI,C=IT";
    public static final Instant NOW = Instant.parse("2018-01-01T00:00:00.00Z");


    protected Supplier<AssertionError> assertionError(String message) {
        return () -> new AssertionError(message);
    }


    // Great okay, this would be my test

    // Find an existing user

    // Link the certificate

    // My change to the notification should be implemented when link and unlink is called.

    // Check if a notification has been made

    @Test
    public void certificateUpdateNotificationTest() {
        IamAccount testAccount = accountRepo.findByUsername(TEST)
            .orElseThrow(assertionError(EXPECTED_USER_NOT_FOUND));

        IamX509Certificate cert = new IamX509Certificate();
        cert.setLabel("label");
        cert.setSubjectDn(TEST_0_SUBJECT);
        cert.setIssuerDn(TEST_0_ISSUER);

        List<IamX509Certificate> certs = Lists.newArrayList(cert);
        testAccount.linkX509Certificates(certs);
        accountRepo.save(testAccount);

    }



}
