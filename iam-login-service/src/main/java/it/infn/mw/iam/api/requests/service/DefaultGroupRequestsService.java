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
package it.infn.mw.iam.api.requests.service;

import static it.infn.mw.iam.core.IamGroupRequestStatus.APPROVED;
import static it.infn.mw.iam.core.IamGroupRequestStatus.PENDING;
import static it.infn.mw.iam.core.IamGroupRequestStatus.REJECTED;

import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Page;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import com.google.common.collect.ImmutableTable;
import com.google.common.collect.Lists;
import com.google.common.collect.Table;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.api.requests.GroupRequestConverter;
import it.infn.mw.iam.api.requests.GroupRequestUtils;
import it.infn.mw.iam.api.requests.exception.InvalidGroupRequestStatusError;
import it.infn.mw.iam.api.requests.model.GroupRequestDto;
import it.infn.mw.iam.audit.events.group.request.GroupRequestApprovedEvent;
import it.infn.mw.iam.audit.events.group.request.GroupRequestCreatedEvent;
import it.infn.mw.iam.audit.events.group.request.GroupRequestDeletedEvent;
import it.infn.mw.iam.audit.events.group.request.GroupRequestRejectedEvent;
import it.infn.mw.iam.core.IamGroupRequestStatus;
import it.infn.mw.iam.core.time.TimeProvider;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.notification.NotificationFactory;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamGroupRequest;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRequestRepository;

@Service
public class DefaultGroupRequestsService implements GroupRequestsService {

  @Autowired
  public IamGroupRequestRepository groupRequestRepository;

  @Autowired
  private IamGroupRepository groupRepository;

  @Autowired
  private IamAccountService accountService;

  @Autowired
  private GroupRequestConverter converter;

  @Autowired
  private AccountUtils accountUtils;

  @Autowired
  private GroupRequestUtils groupRequestUtils;

  @Autowired
  private NotificationFactory notificationFactory;

  @Autowired
  private TimeProvider timeProvider;

  @Autowired
  private ApplicationEventPublisher eventPublisher;

  private static final Table<IamGroupRequestStatus, IamGroupRequestStatus, Boolean> ALLOWED_STATE_TRANSITIONS =
      new ImmutableTable.Builder<IamGroupRequestStatus, IamGroupRequestStatus, Boolean>()
        .put(PENDING, APPROVED, true)
        .put(PENDING, REJECTED, true)
        .build();

  @Override
  public GroupRequestDto createGroupRequest(GroupRequestDto groupRequest) {

    Optional<IamAccount> account = accountUtils.getAuthenticatedUserAccount();
    Optional<IamGroup> group = groupRepository.findByName(groupRequest.getGroupName());

    if (account.isPresent()) {
      groupRequest.setUsername(account.get().getUsername());
    }

    groupRequestUtils.checkRequestAlreadyExist(groupRequest);
    groupRequestUtils.checkUserMembership(groupRequest);

    IamGroupRequest result = new IamGroupRequest();

    if (account.isPresent() && group.isPresent()) {
      IamGroupRequest iamGroupRequest = new IamGroupRequest();
      iamGroupRequest.setUuid(UUID.randomUUID().toString());
      iamGroupRequest.setAccount(account.get());
      iamGroupRequest.setGroup(group.get());
      iamGroupRequest.setNotes(groupRequest.getNotes());
      iamGroupRequest.setStatus(PENDING);
      
      Date creationTime = new Date(timeProvider.currentTimeMillis());
      iamGroupRequest.setCreationTime(creationTime);
      iamGroupRequest.setLastUpdateTime(creationTime);
      
      result = groupRequestRepository.save(iamGroupRequest);
      notificationFactory.createAdminHandleGroupRequestMessage(iamGroupRequest);
      eventPublisher.publishEvent(new GroupRequestCreatedEvent(this, result));
    }
    return converter.fromEntity(result);
  }

  @Override
  public void deleteGroupRequest(String requestId) {
    IamGroupRequest request = groupRequestUtils.getGroupRequest(requestId);

    groupRequestRepository.deleteById(request.getId());
    eventPublisher.publishEvent(new GroupRequestDeletedEvent(this, request));
  }

  @Override
  public GroupRequestDto approveGroupRequest(String requestId) {
    IamGroupRequest request = groupRequestUtils.getGroupRequest(requestId);

    IamAccount account = request.getAccount();
    IamGroup group = request.getGroup();

    accountService.addToGroup(account, group);

    request = updateGroupRequestStatus(request, APPROVED);
    notificationFactory.createGroupMembershipApprovedMessage(request);
    eventPublisher.publishEvent(new GroupRequestApprovedEvent(this, request));

    return converter.fromEntity(request);
  }

  @Override
  public GroupRequestDto rejectGroupRequest(String requestId, String motivation) {
    IamGroupRequest request = groupRequestUtils.getGroupRequest(requestId);
    groupRequestUtils.validateRejectMotivation(motivation);

    request.setMotivation(motivation);
    request = updateGroupRequestStatus(request, REJECTED);
    notificationFactory.createGroupMembershipRejectedMessage(request);
    eventPublisher.publishEvent(new GroupRequestRejectedEvent(this, request));

    return converter.fromEntity(request);
  }

  @Override
  public GroupRequestDto getGroupRequestDetails(String requestId) {
    IamGroupRequest request = groupRequestUtils.getGroupRequest(requestId);
    return converter.fromEntity(request);
  }

  @Override
  public ListResponseDTO<GroupRequestDto> listGroupRequests(String username, String groupName,
      String status, OffsetPageable pageRequest) {
    Optional<String> usernameFilter = Optional.ofNullable(username);
    Optional<String> groupNameFilter = Optional.ofNullable(groupName);
    Optional<String> statusFilter = Optional.ofNullable(status);

    Set<String> managedGroups = Collections.emptySet();

    if (!groupRequestUtils.isPrivilegedUser()) {
      Optional<IamAccount> userAccount = accountUtils.getAuthenticatedUserAccount();

      if (userAccount.isPresent()) {
        managedGroups = groupRequestUtils.getManagedGroups();
        if (managedGroups.isEmpty()) {
          usernameFilter = Optional.of(userAccount.get().getUsername());
        }
      }
    }

    List<GroupRequestDto> results = Lists.newArrayList();

    Page<IamGroupRequest> pagedResults = lookupGroupRequests(usernameFilter, groupNameFilter,
        statusFilter, managedGroups, pageRequest);

    pagedResults.getContent().forEach(request -> results.add(converter.fromEntity(request)));

    ListResponseDTO.Builder<GroupRequestDto> builder = ListResponseDTO.builder();
    return builder.resources(results).fromPage(pagedResults, pageRequest).build();
  }

  private IamGroupRequest updateGroupRequestStatus(IamGroupRequest request,
      IamGroupRequestStatus status) {

    if (!ALLOWED_STATE_TRANSITIONS.contains(request.getStatus(), status)) {
      throw new InvalidGroupRequestStatusError(
          String.format("Invalid group request transition: %s -> %s", request.getStatus(), status));
    }
    request.setStatus(status);
    request.setLastUpdateTime(new Date(timeProvider.currentTimeMillis()));
    return groupRequestRepository.save(request);
  }

  static Specification<IamGroupRequest> baseSpec() {
    return (req, cq, cb) -> cb.conjunction();
  }

  static Specification<IamGroupRequest> forUser(String username) {
    return (req, cq, cb) -> cb.equal(req.get("account").get("username"), username);
  }

  static Specification<IamGroupRequest> forGroupName(String groupName) {
    return (req, cq, cb) -> cb.equal(req.get("group").get("name"), groupName);
  }

  static Specification<IamGroupRequest> forGroupIds(Collection<String> groupIds) {
    return (req, cq, cb) -> req.get("group").get("uuid").in(groupIds);
  }

  static Specification<IamGroupRequest> withStatus(String status) {
    return (req, cq, cb) -> cb.equal(req.get("status"), IamGroupRequestStatus.valueOf(status));
  }

  private Page<IamGroupRequest> lookupGroupRequests(Optional<String> usernameFilter,
      Optional<String> groupNameFilter, Optional<String> statusFilter, Set<String> managedGroups,
      OffsetPageable pageRequest) {

    Specification<IamGroupRequest> spec = baseSpec();

    if (!managedGroups.isEmpty()) {
      spec = spec.and(forGroupIds(managedGroups));
    }

    if (usernameFilter.isPresent()) {
      spec = spec.and(forUser(usernameFilter.get()));
    }

    if (groupNameFilter.isPresent()) {
      spec = spec.and(forGroupName(groupNameFilter.get()));
    }

    if (statusFilter.isPresent()) {
      spec = spec.and(withStatus(statusFilter.get()));
    }

    return groupRequestRepository.findAll(spec, pageRequest);
  }

}
