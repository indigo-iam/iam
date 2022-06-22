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

import java.util.Optional;

import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.scim.model.ScimSshKey;
import it.infn.mw.iam.persistence.model.IamSshKey;
import it.infn.mw.iam.util.ssh.RSAPublicKeyUtils;

@Service
public class SshKeyConverter implements Converter<ScimSshKey, IamSshKey> {

  @Override
  public IamSshKey entityFromDto(ScimSshKey scim) {

    IamSshKey sshKey = new IamSshKey();

    sshKey.setLabel(scim.getDisplay());
    sshKey.setValue(scim.getValue());
    sshKey.setFingerprint(scim.getFingerprint());

    if (scim.getValue() != null) {
      sshKey.setFingerprint(RSAPublicKeyUtils.getSHA256Fingerprint(scim.getValue()));
    }
    sshKey.setPrimary(Optional.ofNullable(scim.isPrimary()).orElse(Boolean.FALSE));
    sshKey.setAccount(null);

    return sshKey;
  }

  @Override
  public ScimSshKey dtoFromEntity(IamSshKey entity) {

    return ScimSshKey.builder()
      .display(entity.getLabel())
      .primary(entity.isPrimary())
      .value(entity.getValue())
      .fingerprint(entity.getFingerprint())
      .created(entity.getCreationTime())
      .lastModified(entity.getLastUpdateTime())
      .build();
  }
}
