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
package it.infn.mw.iam.persistence.repository;

import java.util.Date;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.model.IamAupSignature;

@Component
public class IamAupSignatureRepositoryImpl implements IamAupSignatureRepositoryCustom {

  @Autowired
  IamAupSignatureRepository signatureRepo;

  @Autowired
  IamAccountRepository accountRepo;

  @Override
  public Optional<IamAupSignature> findSignatureForAccount(IamAup aup, IamAccount account) {

    return signatureRepo.findByAupAndAccount(aup, account);
  }

  private IamAupSignature createSignature(IamAup aup, IamAccount account, Date currentTime) {

    IamAupSignature newSignature = new IamAupSignature();
    newSignature.setAccount(account);
    newSignature.setAup(aup);
    newSignature.setSignatureTime(currentTime);
    account.setAupSignature(newSignature);
    accountRepo.save(account);
    return newSignature;
  }

  private IamAupSignature updateSignature(IamAccount account, Date currentTime) {

    account.getAupSignature().setSignatureTime(currentTime);
    accountRepo.save(account);
    return account.getAupSignature();
  }

  private void deleteSignature(IamAccount account) {

    signatureRepo.delete(account.getAupSignature());
    account.setAupSignature(null);
    accountRepo.save(account);
  }

  @Override
  public IamAupSignature createSignatureForAccount(IamAup aup, IamAccount account,
      Date currentTime) {

    Optional<IamAupSignature> signature = signatureRepo.findByAupAndAccount(aup, account);

    if (signature.isEmpty()) {
      return createSignature(aup, account, currentTime);
    }
    return updateSignature(account, currentTime);
  }

  @Override
  public void deleteSignatureForAccount(IamAup aup, IamAccount account) {

    signatureRepo.findByAupAndAccount(aup, account)
      .orElseThrow(() -> new IamAupSignatureNotFoundError(account));
    deleteSignature(account);
  }

}
