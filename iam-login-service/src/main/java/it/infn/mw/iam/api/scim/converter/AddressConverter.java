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

import it.infn.mw.iam.api.scim.model.ScimAddress;
import it.infn.mw.iam.persistence.model.IamAddress;

@Service
public class AddressConverter implements Converter<ScimAddress, IamAddress> {

  @Override
  public IamAddress entityFromDto(ScimAddress scim) {

    IamAddress address = new IamAddress();

    address.setCountry(scim.getCountry());
    address.setFormatted(scim.getFormatted());
    address.setLocality(scim.getLocality());
    address.setCountry(scim.getCountry());
    address.setPostalCode(scim.getPostalCode());
    address.setRegion(scim.getRegion());
    address.setStreetAddress(scim.getStreetAddress());

    return address;
  }

  @Override
  public ScimAddress dtoFromEntity(IamAddress entity) {

    return ScimAddress.builder()
      .country(entity.getCountry())
      .formatted(entity.getFormatted())
      .locality(entity.getLocality())
      .postalCode(entity.getPostalCode())
      .region(entity.getRegion())
      .streetAddress(entity.getStreetAddress())
      .build();
  }

}
