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
package it.infn.mw.iam.api.aup.model;

import org.apache.commons.lang.NotImplementedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.scim.converter.Converter;
import it.infn.mw.iam.persistence.model.IamAupSignature;


@Service
public class AupSignatureConverter implements Converter<AupSignatureDTO, IamAupSignature> {

  final AupConverter aupConverter;

  @Autowired
  public AupSignatureConverter(AupConverter aupConverter) {
    this.aupConverter = aupConverter;
  }

  @Override
  public IamAupSignature entityFromDto(AupSignatureDTO dto) {
    throw new NotImplementedException();
  }

  @Override
  public AupSignatureDTO dtoFromEntity(IamAupSignature signature) {

    AupSignatureDTO sigDto = new AupSignatureDTO();
    AupDTO aupDto = aupConverter.dtoFromEntity(signature.getAup());
    sigDto.setAup(aupDto);
    AccountDTO accountDto = new AccountDTO();

    accountDto.setName(signature.getAccount().getUserInfo().getName());
    accountDto.setUsername(signature.getAccount().getUsername());
    accountDto.setUuid(signature.getAccount().getUuid());
    sigDto.setAccount(accountDto);
    sigDto.setSignatureTime(signature.getSignatureTime());

    return sigDto;
  }

}
