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
package it.infn.mw.iam.test.ext_authn.saml.jit_account_provisioning;


import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import it.infn.mw.iam.authn.saml.CleanInactiveProvisionedAccounts;
import it.infn.mw.iam.core.time.TimeProvider;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;

@RunWith(MockitoJUnitRunner.class)
public class JitUserCleanupTests {

  public static final int NUM_DAYS = 15;

  @Mock
  private IamAccountService accountService;

  @Mock
  private TimeProvider timeProvider;

  @Captor
  ArgumentCaptor<Date> dateArgumentCaptor;

  @Captor
  ArgumentCaptor<IamAccount> iamAccountArgumentCaptor;

  private CleanInactiveProvisionedAccounts cleanupTask;

  @Before
  public void setup() {
    when(timeProvider.currentTimeMillis()).thenReturn(System.currentTimeMillis());
    cleanupTask = new CleanInactiveProvisionedAccounts(timeProvider, accountService, NUM_DAYS);

  }


  @Test(expected = IllegalArgumentException.class)
  public void testLifetimeInDaysSanityChecks() {
    try {
      cleanupTask = new CleanInactiveProvisionedAccounts(timeProvider, accountService, 0);
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), Matchers.equalTo("inactiveUserLifetimeInDays must be > 0"));
      throw e;
    }
  }
  
  @Test(expected= NullPointerException.class)
  public void testNullTimeProviderSanityChecks() {
    try {
      cleanupTask = new CleanInactiveProvisionedAccounts(null, accountService, 1);
    } catch (NullPointerException e) {
      assertThat(e.getMessage(), Matchers.equalTo("null timeProvider"));
      throw e;
    }
  }
  
  @Test(expected= NullPointerException.class)
  public void testAccountServiceSanityChecks() {
    try {
      cleanupTask = new CleanInactiveProvisionedAccounts(timeProvider, null, 1);
    } catch (NullPointerException e) {
      assertThat(e.getMessage(), Matchers.equalTo("null accountService"));
      throw e;
    }
  }

  @Test
  public void testExpirationDateComputation() {

    long now = System.currentTimeMillis();

    LocalDateTime currentDateTime =
        LocalDateTime.ofInstant(Instant.ofEpochMilli(now), ZoneId.systemDefault());

    when(timeProvider.currentTimeMillis()).thenReturn(now);

    cleanupTask.run();

    LocalDateTime numDaysAgo = currentDateTime.minusDays(NUM_DAYS);

    Mockito.verify(accountService)
      .deleteInactiveProvisionedUsersSinceTime(dateArgumentCaptor.capture());

    Instant computedDateInstant = dateArgumentCaptor.getValue().toInstant();

    assertTrue(computedDateInstant
      .isAfter(numDaysAgo.minusSeconds(1).atZone(ZoneId.systemDefault()).toInstant()));

    assertTrue(computedDateInstant
      .isBefore(numDaysAgo.plusSeconds(1).atZone(ZoneId.systemDefault()).toInstant()));

  }

  @Test
  public void testSomethingToCleanup() {

    IamAccount anAccount = IamAccount.newAccount();

    when(accountService.deleteInactiveProvisionedUsersSinceTime(any()))
      .thenReturn(asList(anAccount));
    
    cleanupTask.run();

  }


}
