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
package it.infn.mw.iam.test.api.aup;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.lessThan;
import static org.hamcrest.Matchers.greaterThan;

import java.util.Date;
import java.util.Optional;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import static org.mockito.ArgumentMatchers.any;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.beans.factory.annotation.Autowired;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.model.IamAupSignature;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.persistence.repository.IamAupSignatureRepository;
import it.infn.mw.iam.service.aup.DefaultAupSignatureCheckService;
import it.infn.mw.iam.test.util.MockTimeProvider;

@RunWith(MockitoJUnitRunner.class)
public class AupServiceTests {

  @Mock
  private IamAccountRepository accountRepo;

  @Mock
  private IamAupRepository aupRepo;

  @Mock
  private IamAupSignatureRepository signatureRepo;

  @Autowired
  private MockTimeProvider mockTimeProvider;

  @Autowired
  private DefaultAupSignatureCheckService aupService;

  private IamAccount account = new IamAccount();

  private IamAup aup = new IamAup();;

  private static final Date NOW = new Date();


  @Before
  public void setup() {
    MockTimeProvider mockTimeProvider = new MockTimeProvider();
    mockTimeProvider.setTime(NOW.getTime());

    Integer dayShift = -360;
    Date dateUpdateAUP = new Date();
    dateUpdateAUP.setTime(NOW.getTime() + ((long) dayShift * (24 * 60 * 60) * 1000));

    aup.setCreationTime(dateUpdateAUP);
    aup.setLastUpdateTime(dateUpdateAUP);
    aup.setSignatureValidityInDays(Long.valueOf(180));
    when(aupRepo.findDefaultAup()).thenReturn(Optional.of(aup));

    aupService = new DefaultAupSignatureCheckService(aupRepo, signatureRepo, mockTimeProvider);
  }

  @Test()
  public void aupSignatureValidTest() {
    Integer daysShiftSignature = -60;
    Date date = new Date();
    date.setTime(NOW.getTime() + (long) daysShiftSignature * (24 * 60 * 60) * 1000);

    IamAupSignature firma = new IamAupSignature();
    firma.setSignatureTime(date);
    when(signatureRepo.findByAupAndAccount(any(), any())).thenReturn(Optional.of(firma));

    IamAccount account = new IamAccount();
    account.setAupSignature(firma);
    int daysRemainingSignatureCalculated = aupService.getRemainingDaysSignatureExpiration(account);
    assertThat(daysRemainingSignatureCalculated, notNullValue());
    assertThat(daysRemainingSignatureCalculated, is(greaterThan(0)));
  }

  @Test()
  public void aupSignatureExpiredTest() {
    Integer daysShiftSignature = -200;
    Date date = new Date();
    date.setTime(NOW.getTime() + ((long) daysShiftSignature * (24 * 60 * 60) * 1000));

    IamAupSignature firma = new IamAupSignature();
    firma.setSignatureTime(date);
    when(signatureRepo.findByAupAndAccount(any(), any())).thenReturn(Optional.of(firma));

    account.setAupSignature(firma);
    int daysRemainingSignatureCalculated = aupService.getRemainingDaysSignatureExpiration(account);
    assertThat(daysRemainingSignatureCalculated, notNullValue());
    assertThat(daysRemainingSignatureCalculated, is(lessThan(0)));
  }

  @Test()
  public void aupSignatureNoExistTest() {
    IamAccount account = new IamAccount();
    int daysRemainingSignatureCalculated = aupService.getRemainingDaysSignatureExpiration(account);
    assertThat(daysRemainingSignatureCalculated, notNullValue());
    assertThat(daysRemainingSignatureCalculated, is(equalTo(-Integer.MAX_VALUE)));
  }

  @Test()
  public void aupNoExistTest() {
    when(aupRepo.findDefaultAup()).thenReturn(null);

    IamAccount account = new IamAccount();
    int daysRemainingSignatureCalculated = aupService.getRemainingDaysSignatureExpiration(account);
    assertThat(daysRemainingSignatureCalculated, notNullValue());
    assertThat(daysRemainingSignatureCalculated, is(equalTo(Integer.MAX_VALUE)));
  }

  @Test()
  public void aupUpdateNeedNewSignatureTest() {
    aup.setLastUpdateTime(NOW);
    when(aupRepo.findDefaultAup()).thenReturn(Optional.of(aup));

    Integer daysShiftSignature = -10;
    Date date = new Date();
    date.setTime(NOW.getTime() + ((long) daysShiftSignature * (24 * 60 * 60) * 1000));

    IamAupSignature firma = new IamAupSignature();
    firma.setSignatureTime(date);

    account.setAupSignature(firma);
    int daysRemainingSignatureCalculated = aupService.getRemainingDaysSignatureExpiration(account);
    assertThat(daysRemainingSignatureCalculated, is(lessThan(0)));
  }
}

