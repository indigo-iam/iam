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

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.Date;
import java.util.Optional;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.model.IamAupSignature;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.persistence.repository.IamAupSignatureNotFoundError;
import it.infn.mw.iam.persistence.repository.IamAupSignatureRepository;
import it.infn.mw.iam.test.api.aup.AupTestSupport;
import it.infn.mw.iam.test.util.annotation.IamNoMvcTest;


@RunWith(SpringRunner.class)
@IamNoMvcTest
public class IamAupSignatureRepositoryTests extends AupTestSupport {

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
  public void noSignatureRecordWithoutDefaultAup() {

    IamAccount testAccount = findTestAccount();

    Optional<IamAupSignature> sig = repo.findSignatureForAccount(testAccount);

    assertThat(sig.isPresent(), is(false));
  }

  @Test(expected = AssertionError.class)
  public void signatureCreationWithoutDefaultAupRaisesException() {
    IamAccount testAccount = findTestAccount();
    try {
      repo.createSignatureForAccount(testAccount, new Date());
    } catch (Exception e) {
      assertThat(e.getMessage(),
          equalTo("Default AUP not found in database, cannot create signature"));
      throw e;
    }
  }


  @Test
  public void signatureCreationWorks() {
    IamAup aup = buildDefaultAup();
    aupRepo.save(aup);

    IamAccount testAccount = findTestAccount();
    Date now = new Date();
    repo.createSignatureForAccount(testAccount, new Date());

    IamAupSignature sig = repo.findSignatureForAccount(testAccount)
      .orElseThrow(() -> new AssertionError("Expected signature not found in database"));
    
    assertThat(sig.getAccount(), equalTo(testAccount));
    assertThat(sig.getAup(), equalTo(aup));
    assertThat(testAccount.getAupSignature(), equalTo(sig));
    
    assertThat(sig.getSignatureTime(), equalTo(now));
  }

  @Test
  public void signatureCreationCanBeInvokedMultipleTimes() {
    IamAup aup = buildDefaultAup();
    aupRepo.save(aup);

    IamAccount testAccount = findTestAccount();
    Date now = new Date();
    repo.createSignatureForAccount(testAccount, now);

    IamAupSignature sig = repo.findSignatureForAccount(testAccount)
      .orElseThrow(() -> new AssertionError("Expected signature not found in database"));

    assertThat(sig.getAccount(), equalTo(testAccount));
    assertThat(sig.getAup(), equalTo(aup));
    assertThat(sig.getSignatureTime(), equalTo(now));
    
    now = new Date();
    repo.createSignatureForAccount(testAccount, now);
    
    sig = repo.findSignatureForAccount(testAccount)
        .orElseThrow(() -> new AssertionError("Expected signature not found in database"));
    
    assertThat(sig.getSignatureTime(), equalTo(now));
  }

  @Test(expected = IamAupSignatureNotFoundError.class)
  public void signatureUpdateWithoutDefaultAupRaisesException() {
    IamAccount testAccount = findTestAccount();
    
    try {
      repo.updateSignatureForAccount(testAccount, new Date());
    } catch (Exception e) {
      assertThat(e.getMessage(), equalTo("AUP signature not found for user 'test'"));
      throw e;
    }
  }

  @Test(expected = IamAupSignatureNotFoundError.class)
  public void signatureUpdateWithoutSignatureRecordRaisesException() {
    IamAup aup = buildDefaultAup();
    aupRepo.save(aup);
    IamAccount testAccount = findTestAccount();
    try {
      repo.updateSignatureForAccount(testAccount, new Date());
    } catch (Exception e) {
      assertThat(e.getMessage(), equalTo("AUP signature not found for user 'test'"));
      throw e;
    }
  }

  @Test
  public void signatureUpdateUpdatesSignatureTime() throws InterruptedException {
    IamAup aup = buildDefaultAup();
    aupRepo.save(aup);
    IamAccount testAccount = findTestAccount();

    IamAupSignature sig = repo.createSignatureForAccount(testAccount, new Date());
    
    Date updateTime = new Date();
    sig = repo.updateSignatureForAccount(testAccount, updateTime);
    assertThat(sig.getSignatureTime(), equalTo(updateTime));
  }

}
