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
  IamAupSignatureRepository repo;

  @Autowired
  IamAupRepository aupRepo;
  
  @Override
  public Optional<IamAupSignature> findSignatureForAccount(IamAccount account) {

    Optional<IamAup> aup = aupRepo.findDefaultAup();

    if (!aup.isPresent()) {
      return Optional.empty();
    }

    return repo.findByAupAndAccount(aup.get(), account);
  }

  private IamAupSignature createSignatureForAccount(IamAup aup, IamAccount account) {
    IamAupSignature newSignature = new IamAupSignature();
    newSignature.setAccount(account);
    newSignature.setAup(aup);
    account.setAupSignature(newSignature);
    return newSignature;
  }

  @Override
  public IamAupSignature createSignatureForAccount(IamAccount account, Date currentTime) {
    IamAup aup = aupRepo.findDefaultAup()
      .orElseThrow(() -> new IllegalStateException(
          "Default AUP not found in database, cannot create signature"));

    IamAupSignature signature = repo.findSignatureForAccount(account)
      .orElseGet(() -> createSignatureForAccount(aup, account));

    signature.setSignatureTime(currentTime);
    
    repo.save(signature);
    return signature;
  }

  @Override
  public IamAupSignature updateSignatureForAccount(IamAccount account, Date currentTime) {

    IamAupSignature signature = findSignatureForAccount(account)
      .orElseThrow(() -> new IamAupSignatureNotFoundError(account));


    signature.setSignatureTime(currentTime);
    repo.save(signature);

    return signature;
  }

}
