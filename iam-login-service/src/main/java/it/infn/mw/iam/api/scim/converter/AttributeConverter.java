package it.infn.mw.iam.api.scim.converter;

import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.scim.model.ScimAttribute;
import it.infn.mw.iam.persistence.model.IamAttribute;

@Service
public class AttributeConverter implements Converter<ScimAttribute, IamAttribute> {

  @Override
  public IamAttribute entityFromDto(ScimAttribute dto) {

    IamAttribute entity = new IamAttribute();
    entity.setName(dto.getName());
    entity.setValue(dto.getValue());
    return entity;
  }

  @Override
  public ScimAttribute dtoFromEntity(IamAttribute entity) {

    return ScimAttribute.builder().withName(entity.getName()).withVaule(entity.getValue()).build();
  }

}
