package it.infn.mw.iam.api.scim.converter;

import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.api.scim.model.ScimGroupRef;
import it.infn.mw.iam.api.scim.model.ScimIndigoGroup;
import it.infn.mw.iam.api.scim.model.ScimMemberRef;
import it.infn.mw.iam.api.scim.model.ScimMeta;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;

@Service
public class GroupConverter implements Converter<ScimGroup, IamGroup> {

  private final ScimResourceLocationProvider resourceLocationProvider;

  @Autowired
  public GroupConverter(ScimResourceLocationProvider rlp) {

    this.resourceLocationProvider = rlp;
  }

  /**
   * <ul>
   * <li>Mutable fields: name</li>
   * <li>Immutable fields: id, uuid, creationtime</li>
   * <li>Read-only fields: lastupdatetime, accounts</li>
   * <li>Not managed via SCIM: description</li>
   * </ul>
   */
  @Override
  public IamGroup fromScim(ScimGroup scimGroup) {

    IamGroup group = new IamGroup();

    group.setName(scimGroup.getDisplayName());

    return group;
  }

  @Override
  public ScimGroup toScim(IamGroup entity) {

    ScimMeta meta = ScimMeta.builder(entity.getCreationTime(), entity.getLastUpdateTime())
      .location(resourceLocationProvider.groupLocation(entity.getUuid()))
      .resourceType(ScimGroup.RESOURCE_TYPE)
      .build();

    Set<ScimMemberRef> members = new HashSet<>();

    for (IamAccount account : entity.getAccounts()) {
      ScimMemberRef memberRef = new ScimMemberRef.Builder().value(account.getUuid())
        .display(account.getUsername())
        .ref(resourceLocationProvider.userLocation(account.getUuid()))
        .build();
      members.add(memberRef);
    }

    for (IamGroup subgroup : entity.getChildrenGroups()) {
      ScimMemberRef memberRef = new ScimMemberRef.Builder().display(subgroup.getName())
        .value(subgroup.getUuid())
        .ref(resourceLocationProvider.groupLocation(subgroup.getUuid()))
        .build();
      members.add(memberRef);
    }

    IamGroup iamParentGroup = entity.getParentGroup();
    ScimIndigoGroup scimParentGroup = null;

    if (iamParentGroup != null) {
      ScimGroupRef parentGroupRef = ScimGroupRef.builder()
        .display(iamParentGroup.getName())
        .value(iamParentGroup.getUuid())
        .ref(resourceLocationProvider.groupLocation(iamParentGroup.getUuid()))
        .build();

      scimParentGroup = ScimIndigoGroup.getBuilder().parentGroup(parentGroupRef).build();
    }

    return ScimGroup.builder(entity.getName())
      .id(entity.getUuid())
      .meta(meta)
      .setMembers(members)
      .indigoGroup(scimParentGroup)
      .build();
  }

}
