package it.infn.mw.iam.api.scim.converter;

import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.scim.model.ScimAuthority;
import it.infn.mw.iam.persistence.model.IamAuthority;

@Service
public class AuthorityConverter implements Converter<ScimAuthority, IamAuthority> {

  @Override
  public IamAuthority fromScim(ScimAuthority scim) {

    IamAuthority iamAuth = new IamAuthority(scim.getAuthority());
    iamAuth.setId(scim.getId());

    return iamAuth;
  }

  @Override
  public ScimAuthority toScim(IamAuthority entity) {

    return ScimAuthority.builder().authority(entity.getAuthority()).id(entity.getId()).build();
  }

}
