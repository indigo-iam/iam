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
package it.infn.mw.iam.service.aup;

import static java.util.Objects.isNull;

import java.util.Date;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.core.time.TimeProvider;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.model.IamAupSignature;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.persistence.repository.IamAupSignatureRepository;

@Service
public class DefaultAupSignatureCheckService implements AUPSignatureCheckService {

  public static final Logger LOG = LoggerFactory.getLogger(DefaultAupSignatureCheckService.class);

  final IamAupRepository aupRepo;
  final IamAupSignatureRepository signatureRepo;
  final TimeProvider timeProvider;

  @Autowired
  public DefaultAupSignatureCheckService(IamAupRepository aupRepo,
      IamAupSignatureRepository signatureRepo, TimeProvider timeProvider) {
    this.aupRepo = aupRepo;
    this.signatureRepo = signatureRepo;
    this.timeProvider = timeProvider;
  }

  @Override
  public Long getRemainingTimeToSignatureExpiration(IamAccount account) {
    Optional<IamAup> aup = aupRepo.findDefaultAup();

    if (isNull(aup) || !aup.isPresent()
        || (aup.isPresent() && aup.get().getSignatureValidityInDays() == 0)) {
      LOG.debug("AUP signature not needed for account '{}': AUP is not defined",
          account.getUsername());
      return Long.MAX_VALUE;
    }

    if (isNull(account.getAupSignature())) {
      LOG.debug("AUP signature needed for account '{}': no signature record found for user",
          account.getUsername());
      return Long.MIN_VALUE;
    }

    Date signatureTime = account.getAupSignature().getSignatureTime();
    Date aupLastModifiedTime = aup.get().getLastUpdateTime();
    Long signatureValidityInDays = aup.get().getSignatureValidityInDays();

    if (aupLastModifiedTime.getTime() >= signatureTime.getTime()) {
      LOG.debug(
          "AUP signature needed for account '{}': signature record expiration after AUP update",
          account.getUsername());
      return Long.MIN_VALUE;
    }

    Long daysLeftBeforeSignAup =
        calculateDaysLeft(signatureValidityInDays, signatureTime.getTime());

    if (daysLeftBeforeSignAup > 0) {

      if (signatureValidityInDays > 0) {

        Date signatureValidTime = new Date(signatureTime.getTime() + signatureValidityInDays);

        // The signature was on the last version of the AUP
        Date now = new Date(timeProvider.currentTimeMillis());
        boolean signatureNeeded = now.compareTo(signatureValidTime) > 0;
        String signatureNeededString = (signatureNeeded ? "needed" : "not needed");
        LOG.debug(
            "AUP signature {} for account '{}': Now '{}' AUP signature time '{}', AUP signature end of validity '{}'",
            signatureNeededString, account.getUsername(), now, signatureTime, signatureValidTime);
      }

      return daysLeftBeforeSignAup;
    } else {
      LOG.debug(
          "AUP signature needed for account '{}': AUP signature time '{}', AUP last modified time '{}'",
          account.getUsername(), signatureTime, aupLastModifiedTime);

      return daysLeftBeforeSignAup;
    }
  }

  private Long calculateDaysLeft(Long signatureValidityInDays, Long signatureTime) {
    Date expirationDateSignature =
        new Date(signatureTime + TimeUnit.DAYS.toMillis(signatureValidityInDays));
    Date now = new Date(timeProvider.currentTimeMillis());
    Long delta = expirationDateSignature.getTime() - now.getTime();
    // Long resultDaysLeft = TimeUnit.DAYS.convert(delta, TimeUnit.MILLISECONDS);

    return delta;
  }
}
