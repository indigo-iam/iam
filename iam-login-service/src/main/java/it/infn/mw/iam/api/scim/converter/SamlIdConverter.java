package it.infn.mw.iam.api.scim.converter;

import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.scim.model.ScimSamlId;
import it.infn.mw.iam.persistence.model.IamSamlId;

@Service
public class SamlIdConverter implements Converter<ScimSamlId, IamSamlId> {

  @Override
  public IamSamlId fromScim(ScimSamlId scim) {

    IamSamlId samlId = new IamSamlId();
    samlId.setIdpId(scim.getIdpId());
    samlId.setUserId(scim.getUserId());
    samlId.setAttributeId(scim.getAttributeId());
    samlId.setAccount(null);

    return samlId;
  }

  @Override
  public ScimSamlId toScim(IamSamlId entity) {

    return ScimSamlId.builder().idpId(entity.getIdpId()).
        userId(entity.getUserId())
        .attributeId(entity.getAttributeId())
        .build();
  }
}
