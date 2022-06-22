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
package it.infn.mw.iam.api.scim.converter;

import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.scim.model.ScimOidcId;
import it.infn.mw.iam.persistence.model.IamOidcId;

@Service
public class OidcIdConverter implements Converter<ScimOidcId, IamOidcId> {

  @Override
  public IamOidcId entityFromDto(ScimOidcId scim) {

    IamOidcId oidcId = new IamOidcId();
    oidcId.setIssuer(scim.getIssuer());
    oidcId.setSubject(scim.getSubject());
    oidcId.setAccount(null);

    return oidcId;
  }

  @Override
  public ScimOidcId dtoFromEntity(IamOidcId entity) {

    ScimOidcId.Builder builder = ScimOidcId.builder()
      .issuer(entity.getIssuer())
      .subject(entity.getSubject());

    return builder.build();
  }
}
