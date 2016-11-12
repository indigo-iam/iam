package it.infn.mw.iam.api.scim.provisioning;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.scim.converter.GroupConverter;
import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;
import it.infn.mw.iam.api.scim.exception.ScimException;
import it.infn.mw.iam.api.scim.exception.ScimResourceExistsException;
import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;
import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.api.scim.model.ScimListResponse;
import it.infn.mw.iam.api.scim.model.ScimMemberRef;
import it.infn.mw.iam.api.scim.model.ScimPatchOperation;
import it.infn.mw.iam.api.scim.provisioning.paging.OffsetPageable;
import it.infn.mw.iam.api.scim.provisioning.paging.ScimPageRequest;
import it.infn.mw.iam.api.scim.updater.GroupUpdater;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;

@Service
public class ScimGroupProvisioning implements ScimProvisioning<ScimGroup, List<ScimMemberRef>> {

  private final GroupConverter converter;
  private final GroupUpdater updater;

  private final IamGroupRepository groupRepository;
  private final IamAccountRepository accountRepository;

  @Autowired
  public ScimGroupProvisioning(GroupConverter converter, GroupUpdater updater,
      IamGroupRepository groupRepository, IamAccountRepository accountRepository) {

    this.updater = updater;
    this.converter = converter;
    this.groupRepository = groupRepository;
    this.accountRepository = accountRepository;
  }

  private void idSanityChecks(String id) {

    if (id == null) {
      throw new IllegalArgumentException("id cannot be null");
    }

    if (id.trim().isEmpty()) {
      throw new IllegalArgumentException("id cannot be the empty string");
    }
  }

  @Override
  public ScimGroup getById(String id) {

    idSanityChecks(id);

    Optional<IamGroup> group = groupRepository.findByUuid(id);

    if (group.isPresent()) {
      return converter.toScim(group.get());
    }

    throw new ScimResourceNotFoundException("No group mapped to id '" + id + "'");
  }

  @Override
  public ScimGroup create(ScimGroup group) {

    IamGroup iamGroup = new IamGroup();

    Date creationTime = new Date();
    String uuid = UUID.randomUUID().toString();

    iamGroup.setUuid(uuid);
    iamGroup.setName(group.getDisplayName());
    iamGroup.setCreationTime(creationTime);
    iamGroup.setLastUpdateTime(creationTime);
    iamGroup.setAccounts(new HashSet<IamAccount>());

    if (groupRepository.findByName(group.getDisplayName()).isPresent()) {
      throw new ScimResourceExistsException("Duplicated group '" + group.getDisplayName() + "'");
    }

    groupRepository.save(iamGroup);

    return converter.toScim(iamGroup);
  }

  @Override
  public void delete(String id) {

    idSanityChecks(id);

    IamGroup group = groupRepository.findByUuid(id)
      .orElseThrow(() -> new ScimResourceNotFoundException("No group mapped to id '" + id + "'"));

    List<IamAccount> accounts = accountRepository.findByGroupId(group.getId());

    if (!accounts.isEmpty()) {

      throw new ScimException("Not empty group");
    }

    groupRepository.delete(group);
  }

  @Override
  public ScimGroup replace(String id, ScimGroup scimItemToBeReplaced) {

    IamGroup existingGroup = groupRepository.findByUuid(id)
      .orElseThrow(() -> new ScimResourceNotFoundException("No group mapped to id '" + id + "'"));

    /* displayname is required */
    String displayName = scimItemToBeReplaced.getDisplayName();

    if (groupRepository.findByNameWithDifferentId(displayName, id).isPresent()) {
      throw new ScimResourceExistsException(displayName + " is already mappped to another group");
    }

    IamGroup updatedGroup = converter.fromScim(scimItemToBeReplaced);
    /* SCIM resource identifiers cannot be replaced by PUT */
    updatedGroup.setId(existingGroup.getId());
    updatedGroup.setUuid(existingGroup.getUuid());
    updatedGroup.setCreationTime(existingGroup.getCreationTime());
    updatedGroup.setAccounts(existingGroup.getAccounts());
    /* description is not mapped into SCIM group */
    updatedGroup.setDescription(existingGroup.getDescription());

    updatedGroup.touch();

    groupRepository.save(updatedGroup);
    return converter.toScim(updatedGroup);
  }

  @Override
  public ScimListResponse<ScimGroup> list(ScimPageRequest params) {

    if (params.getCount() == 0) {
      int groupCount = groupRepository.countAllGroups();
      return new ScimListResponse<>(Collections.emptyList(), groupCount, 0, 1);
    }

    OffsetPageable op = new OffsetPageable(params.getStartIndex(), params.getCount());

    Page<IamGroup> results = groupRepository.findAll(op);

    List<ScimGroup> resources = new ArrayList<>();

    results.getContent().forEach(g -> resources.add(converter.toScim(g)));

    return new ScimListResponse<>(resources, results.getTotalElements(), resources.size(),
        op.getOffset() + 1);
  }

  public void update(String id, List<ScimPatchOperation<List<ScimMemberRef>>> operations) {

    IamGroup iamGroup = groupRepository.findByUuid(id)
      .orElseThrow(() -> new ScimResourceNotFoundException("No group mapped to id '" + id + "'"));

    updater.update(iamGroup, operations);

  }

}
