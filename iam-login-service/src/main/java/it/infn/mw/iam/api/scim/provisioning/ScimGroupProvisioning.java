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
package it.infn.mw.iam.api.scim.provisioning;

import static com.google.common.collect.Lists.newArrayList;
import static java.lang.String.format;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Service;

import com.google.common.base.Strings;

import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.api.scim.converter.GroupConverter;
import it.infn.mw.iam.api.scim.converter.ScimResourceLocationProvider;
import it.infn.mw.iam.api.scim.exception.IllegalArgumentException;
import it.infn.mw.iam.api.scim.exception.ScimPatchOperationNotSupported;
import it.infn.mw.iam.api.scim.exception.ScimResourceExistsException;
import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;
import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.api.scim.model.ScimListResponse;
import it.infn.mw.iam.api.scim.model.ScimListResponse.ScimListResponseBuilder;
import it.infn.mw.iam.api.scim.model.ScimMemberRef;
import it.infn.mw.iam.api.scim.model.ScimPatchOperation;
import it.infn.mw.iam.api.scim.model.ScimPatchOperation.ScimPatchOperationType;
import it.infn.mw.iam.api.scim.provisioning.paging.ScimPageRequest;
import it.infn.mw.iam.api.scim.updater.Updater;
import it.infn.mw.iam.api.scim.updater.factory.DefaultGroupMembershipUpdaterFactory;
import it.infn.mw.iam.core.group.IamGroupService;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;

@Service
@Transactional
public class ScimGroupProvisioning
    implements ScimProvisioning<ScimGroup, List<ScimMemberRef>> {

  private static final int GROUP_NAME_MAX_LENGTH = 50;
  private static final int GROUP_FULLNAME_MAX_LENGTH = 512;

  private final IamGroupService groupService;
  private final IamAccountService accountService;

  private final GroupConverter converter;

  private final DefaultGroupMembershipUpdaterFactory groupUpdaterFactory;

  private final ScimResourceLocationProvider locationProvider;

  @Autowired
  public ScimGroupProvisioning(IamGroupService groupService, IamAccountService accountService,
      GroupConverter converter, ScimResourceLocationProvider locationProvider, Clock clock) {

    this.accountService = accountService;
    this.groupService = groupService;
    this.converter = converter;

    this.groupUpdaterFactory = new DefaultGroupMembershipUpdaterFactory(accountService);
    this.locationProvider = locationProvider;
  }

  private void patchOperationSanityChecks(ScimPatchOperation<List<ScimMemberRef>> op) {

    if (op.getPath() == null || op.getPath().isEmpty()) {
      throw new ScimPatchOperationNotSupported("empty path value is not currently supported");
    }
    if (!"members".equals(op.getPath())) {
      throw new ScimPatchOperationNotSupported(
          "path value " + op.getPath() + " is not currently supported");
    }

    if (op.getOp().equals(ScimPatchOperationType.replace)) {
      throw new ScimPatchOperationNotSupported("'replace' operation is not currently supported");
    }
  }

  @Override
  public ScimGroup create(ScimGroup group) {

    displayNameSanityChecks(group.getDisplayName());

    IamGroup iamGroup = new IamGroup();
    String uuid = UUID.randomUUID().toString();

    iamGroup.setUuid(uuid);
    iamGroup.setName(group.getDisplayName());

    IamGroup iamParentGroup = null;

    if (group.getIndigoGroup().getParentGroup() != null) {
      String parentGroupUuid = group.getIndigoGroup().getParentGroup().getValue();
      String parentGroupName = group.getIndigoGroup().getParentGroup().getDisplay();

      iamParentGroup = groupService.findByUuid(parentGroupUuid)
        .orElseThrow(() -> new ScimResourceNotFoundException(
            String.format("Parent group '%s' not found", parentGroupUuid)));

      String fullName = String.format("%s/%s", parentGroupName, group.getDisplayName());
      fullNameSanityChecks(fullName);

      iamGroup.setName(fullName);

      iamGroup.setParentGroup(iamParentGroup);
      iamParentGroup.getChildrenGroups().add(iamGroup);

    }

    groupService.createGroup(iamGroup);

    return converter.dtoFromEntity(iamGroup);
  }

  @Override
  public void delete(String id) {
    idSanityChecks(id);
    groupService.deleteGroupByUuid(id);
  }

  private void displayNameSanityChecks(String displayName) {
    if (Strings.isNullOrEmpty(displayName)) {
      throw new IllegalArgumentException("Group displayName cannot be empty");
    }

    if (displayName.contains("/")) {
      throw new IllegalArgumentException("Group displayName cannot contain a slash character");
    }

    if (displayName.length() > GROUP_NAME_MAX_LENGTH) {
      throw new IllegalArgumentException(
          format("Group name length cannot exceed %d characters", GROUP_NAME_MAX_LENGTH));
    }
  }

  private void executePatchOperation(IamGroup group, ScimPatchOperation<List<ScimMemberRef>> op) {

    patchOperationSanityChecks(op);
    groupUpdaterFactory.getUpdatersForPatchOperation(group, op).forEach(Updater::update);

  }



  private void fullNameSanityChecks(String displayName) {
    if (displayName.length() > GROUP_FULLNAME_MAX_LENGTH) {
      throw new IllegalArgumentException(format(
          "Group displayName length cannot exceed %d characters", GROUP_FULLNAME_MAX_LENGTH));
    }

    if (groupService.findByName(displayName).isPresent()) {
      throw new ScimResourceExistsException(format("Duplicated group '%s'", displayName));
    }
  }

  @Override
  public ScimGroup getById(String id) {

    idSanityChecks(id);

    IamGroup group = groupService.findByUuid(id).orElseThrow(noGroupMappedToId(id));

    return converter.dtoFromEntity(group);
  }

  private void idSanityChecks(String id) {

    if (id == null) {
      throw new IllegalArgumentException("id cannot be null");
    }

    if (id.trim().isEmpty()) {
      throw new IllegalArgumentException("id cannot be the empty string");
    }
  }

  private boolean isGroupNameAvailable(String displayName, String id) {

    return !groupService.findByNameWithDifferentId(displayName, id).isPresent();
  }

  @Override
  public ScimListResponse<ScimGroup> list(ScimPageRequest pageRequest) {

    ScimListResponseBuilder<ScimGroup> builder = ScimListResponse.builder();

    if (pageRequest.getCount() == 0) {

      long totalResults = groupService.countAllGroups();
      builder.totalResults(totalResults);

    } else {

      OffsetPageable op = new OffsetPageable(pageRequest.getStartIndex(), pageRequest.getCount());

      Page<IamGroup> results = groupService.findAll(op);

      List<ScimGroup> resources = new ArrayList<>();

      results.getContent().forEach(g -> resources.add(converter.dtoFromEntity(g)));

      builder.resources(resources);
      builder.fromPage(results, op);

    }

    return builder.build();
  }

  private Supplier<ScimResourceNotFoundException> noGroupMappedToId(String id) {
    return () -> new ScimResourceNotFoundException(String.format("No group mapped to id '%s'", id));
  }


  @Override
  public ScimGroup replace(String id, ScimGroup scimItemToBeReplaced) {

    IamGroup oldGroup = groupService.findByUuid(id).orElseThrow(noGroupMappedToId(id));

    String displayName = scimItemToBeReplaced.getDisplayName();
    displayNameSanityChecks(displayName);

    if (!isGroupNameAvailable(displayName, id)) {
      throw new ScimResourceExistsException(displayName + " is already mapped to another group");
    }

    IamGroup newGroup = converter.entityFromDto(scimItemToBeReplaced);
    groupService.updateGroup(oldGroup, newGroup);

    return converter.dtoFromEntity(newGroup);
  }


  @Override
  public void update(String id, List<ScimPatchOperation<List<ScimMemberRef>>> operations) {

    IamGroup iamGroup = groupService.findByUuid(id).orElseThrow(noGroupMappedToId(id));

    operations.forEach(op -> executePatchOperation(iamGroup, op));
  }


  public ScimListResponse<ScimMemberRef> listAccountMembers(String id,
      ScimPageRequest pageRequest) {

    IamGroup iamGroup = groupService.findByUuid(id).orElseThrow(noGroupMappedToId(id));

    ScimListResponseBuilder<ScimMemberRef> results = new ScimListResponseBuilder<>();

    OffsetPageable pr = new OffsetPageable(pageRequest.getStartIndex(), pageRequest.getCount());
    Page<IamAccount> accounts = accountService.fingGroupMembers(iamGroup, pr);

    List<ScimMemberRef> resources = newArrayList();

    for (IamAccount a : accounts.getContent()) {
      resources.add(ScimMemberRef.builder()
        .value(a.getUuid())
        .display(a.getUserInfo().getName())
        .ref(locationProvider.userLocation(a.getUuid()))
        .build());
    }

    results.fromPage(accounts, pr);
    results.resources(resources);
    return results.build();
  }

  public ScimListResponse<ScimMemberRef> listGroupMembers(String id,
      ScimPageRequest pageRequest) {

    IamGroup iamGroup = groupService.findByUuid(id).orElseThrow(noGroupMappedToId(id));

    ScimListResponseBuilder<ScimMemberRef> results = new ScimListResponseBuilder<>();
    OffsetPageable pr = new OffsetPageable(pageRequest.getStartIndex(), pageRequest.getCount());
    Page<IamGroup> subgroups = groupService.findSubgroups(iamGroup, pr);

    List<ScimMemberRef> resources = newArrayList();
    for (IamGroup g : subgroups.getContent()) {
      resources.add(ScimMemberRef.builder()
        .value(g.getUuid())
        .display(g.getName())
        .ref(locationProvider.groupLocation(g.getUuid()))
        .build());
    }

    results.fromPage(subgroups, pr);
    results.resources(resources);
    return results.build();

  }

}
