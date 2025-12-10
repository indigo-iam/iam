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
package it.infn.mw.iam.test.repository;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.model.IamAupSignature;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.persistence.repository.IamAupSignatureRepository;
import it.infn.mw.iam.persistence.repository.IamAupSignatureUpdateError;
import it.infn.mw.iam.test.api.aup.AupTestSupport;
import it.infn.mw.iam.test.util.annotation.IamNoMvcTest;

@ExtendWith(SpringExtension.class)
@IamNoMvcTest
class IamAupSignatureRepositoryTests extends AupTestSupport {

  @Autowired
  private IamAupRepository aupRepo;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private IamAupSignatureRepository repo;


  IamAccount findTestAccount() {
    return accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test user not found"));
  }

  @Test
  void signatureCreationWorks() {
    IamAup aup = buildDefaultAup();
    aupRepo.save(aup);

    IamAccount testAccount = findTestAccount();
    Date now = new Date();
    repo.createSignatureForAccount(aup, testAccount, now);

    IamAupSignature sig = repo.findSignatureForAccount(aup, testAccount)
      .orElseThrow(() -> new AssertionError("Expected signature not found in database"));
    
    assertThat(sig.getAccount(), equalTo(testAccount));
    assertThat(sig.getAup(), equalTo(aup));
    assertThat(testAccount.getAupSignature(), equalTo(sig));
    
    assertThat(sig.getSignatureTime(), equalTo(now));
  }

  @Test
  void signatureCreationCanBeInvokedMultipleTimes() {
    IamAup aup = buildDefaultAup();
    aupRepo.save(aup);

    IamAccount testAccount = findTestAccount();
    Date now = new Date();
    repo.createSignatureForAccount(aup, testAccount, now);

    IamAupSignature sig = repo.findSignatureForAccount(aup, testAccount)
      .orElseThrow(() -> new AssertionError("Expected signature not found in database"));

    assertThat(sig.getAccount(), equalTo(testAccount));
    assertThat(sig.getAup(), equalTo(aup));
    assertThat(sig.getSignatureTime(), equalTo(now));
    
    now = new Date();
    repo.createSignatureForAccount(aup, testAccount, now);
    
    sig = repo.findSignatureForAccount(aup, testAccount)
        .orElseThrow(() -> new AssertionError("Expected signature not found in database"));
    
    assertThat(sig.getSignatureTime(), equalTo(now));
  }

  @Test
  void signatureUpdateUpdatesSignatureTime() {
    IamAup aup = buildDefaultAup();
    aupRepo.save(aup);
    IamAccount testAccount = findTestAccount();

    repo.createSignatureForAccount(aup, testAccount, new Date());

    Date updateTime = new Date();
    IamAupSignature sig = repo.createSignatureForAccount(aup, testAccount, updateTime);
    assertThat(sig.getSignatureTime(), equalTo(updateTime));
  }

  @Test
  void testServiceAccountThrowsExceptionOnAUPSignatureCreation() {
    IamAup aup = buildDefaultAup();
    aupRepo.save(aup);
    IamAccount testAccount = findTestAccount();
    testAccount.setServiceAccount(true);

    Exception exception = assertThrows(IamAupSignatureUpdateError.class,
        () -> repo.createSignatureForAccount(aup, testAccount, new Date()));

    String expectedMessage = "As user 'test' is a service account, AUP signature operation not allowed";
    String actualMessage = exception.getMessage();

    assertTrue(actualMessage.contains(expectedMessage));
  }


  @Test
  void testServiceAccountThrowsExceptionOnDeleteSignatureForAccount() {
    IamAup aup = buildDefaultAup();
    aupRepo.save(aup);
    IamAccount testAccount = findTestAccount();
    repo.createSignatureForAccount(aup, testAccount, new Date());
    testAccount.setServiceAccount(true);

    Exception exception = assertThrows(IamAupSignatureUpdateError.class,
        () -> repo.deleteSignatureForAccount(aup, testAccount));

    String expectedMessage = "As user 'test' is a service account, AUP signature operation not allowed";
    String actualMessage = exception.getMessage();

    assertTrue(actualMessage.contains(expectedMessage));
  }

}
