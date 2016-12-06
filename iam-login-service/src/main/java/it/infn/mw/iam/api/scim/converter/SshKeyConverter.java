package it.infn.mw.iam.api.scim.converter;

import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.scim.model.ScimSshKey;
import it.infn.mw.iam.persistence.model.IamSshKey;
import it.infn.mw.iam.util.ssh.RSAPublicKeyUtils;

@Service
public class SshKeyConverter implements Converter<ScimSshKey, IamSshKey> {

  @Override
  public IamSshKey fromScim(ScimSshKey scim) {

    IamSshKey sshKey = new IamSshKey();

    sshKey.setLabel(scim.getDisplay());
    sshKey.setValue(scim.getValue());

    if (scim.getValue() != null) {
      sshKey.setFingerprint(RSAPublicKeyUtils.getSHA256Fingerprint(scim.getValue()));
    }

    sshKey.setPrimary(scim.isPrimary() != null ? scim.isPrimary() : false);
    sshKey.setAccount(null);

    return sshKey;
  }

  @Override
  public ScimSshKey toScim(IamSshKey entity) {

    return ScimSshKey.builder()
      .display(entity.getLabel())
      .primary(entity.isPrimary())
      .value(entity.getValue())
      .fingerprint(entity.getFingerprint())
      .build();
  }
}
