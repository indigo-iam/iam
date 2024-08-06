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
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.model.IamAupSignature;

public interface IamAupSignatureRepository
    extends PagingAndSortingRepository<IamAupSignature, Long>, IamAupSignatureRepositoryCustom {

  @Query("select ias from IamAupSignature ias join ias.account a where a.active = TRUE and ias.aup = :aup and :signatureTime <= ias.signatureTime and ias.signatureTime < :plusOne")
  List<IamAupSignature> findByAupAndSignatureTime(@Param("aup") IamAup aup,
      @Param("signatureTime") Date signatureTime, @Param("plusOne") Date plusOne);

  Optional<IamAupSignature> findByAupAndAccount(IamAup aup, IamAccount account);

  Long deleteByAup(IamAup aup);

}
