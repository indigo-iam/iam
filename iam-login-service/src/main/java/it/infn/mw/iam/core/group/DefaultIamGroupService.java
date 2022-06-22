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
package it.infn.mw.iam.core.group;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.Sets.newHashSet;
import static java.util.Objects.isNull;

import java.time.Clock;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.audit.events.group.GroupCreatedEvent;
import it.infn.mw.iam.audit.events.group.GroupRemovedEvent;
import it.infn.mw.iam.audit.events.group.GroupReplacedEvent;
import it.infn.mw.iam.audit.events.group.label.GroupLabelRemovedEvent;
import it.infn.mw.iam.audit.events.group.label.GroupLabelSetEvent;
import it.infn.mw.iam.core.group.error.InvalidGroupOperationError;
import it.infn.mw.iam.core.group.error.NoSuchGroupError;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAuthoritiesRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;

@Service
@Transactional
public class DefaultIamGroupService implements IamGroupService, ApplicationEventPublisherAware {

  public static final String GROUP_MANAGER_AUTHORITY_TEMPLATE = "ROLE_GM:%s";

  private final IamGroupRepository groupRepo;
  private final IamAuthoritiesRepository authorityRepo;
  private final IamAccountRepository accountRepo;
  private final Clock clock;

  private ApplicationEventPublisher eventPublisher;

  @Autowired
  public DefaultIamGroupService(IamGroupRepository groupRepo, IamAuthoritiesRepository authRepo,
      IamAccountRepository accountRepo, Clock clock) {
    this.groupRepo = groupRepo;
    this.authorityRepo = authRepo;
    this.accountRepo = accountRepo;
    this.clock = clock;
  }

  @Override
  public IamGroup createGroup(IamGroup g) {
    checkNotNull(g, "Cannot create a null group");
    final Date creationTime = Date.from(clock.instant());

    if (isNull(g.getUuid())) {
      g.setUuid(UUID.randomUUID().toString());
    }
    
    g.setCreationTime(creationTime);
    g.setLastUpdateTime(creationTime);

    g.setChildrenGroups(newHashSet());

    createGroupManagerAuthority(g);
    g = groupRepo.save(g);

    if (!isNull(g.getParentGroup())) {
      groupRepo.save(g.getParentGroup());
    }

    groupCreatedEvent(g);
    return g;
  }

  protected IamAuthority createGroupManagerAuthority(IamGroup g) {
    return authorityRepo.save(new IamAuthority(groupManagerAuthority(g)));
  }


  private void deleteAccountAuthority(IamAccount account, IamAuthority auth) {
    account.getAuthorities().removeIf(a -> a.getAuthority().equals(auth.getAuthority()));
    accountRepo.save(account);
  }

  @Override
  public IamGroup deleteGroup(IamGroup g) {
    checkNotNull(g);

    Long membersCount = groupRepo.countGroupMembersByGroupUuid(g.getUuid());

    if (membersCount > 0L || !g.getChildrenGroups().isEmpty()) {
      throw new InvalidGroupOperationError("Group is not empty");
    }

    IamGroup parent = g.getParentGroup();

    if (!isNull(parent)) {
      parent.getChildrenGroups().remove(g);
      groupRepo.save(parent);
    }

    groupRepo.delete(g);

    deleteGroupManagerAuthority(g);
    groupRemovedEvent(g);
    return g;
  }


  @Override
  public IamGroup deleteGroupByUuid(String uuid) {
    checkNotNull(uuid);

    IamGroup g = groupRepo.findByUuid(uuid)
      .orElseThrow(noSuchGroupException(String.format("No group found for id '%s'", uuid)));

    return deleteGroup(g);
  }



  private void deleteGroupManagerAuthority(IamGroup group) {
    String authorityString = groupManagerAuthority(group);

    Optional<IamAuthority> auth = authorityRepo.findByAuthority(authorityString);

    auth.ifPresent(authority -> {
      accountRepo.findByAuthority(authorityString)
        .forEach(account -> deleteAccountAuthority(account, authority));
      authorityRepo.delete(authority);
    });
  }

  @Override
  public Optional<IamGroup> findByUuid(String uuid) {
    return groupRepo.findByUuid(uuid);
  }

  private void groupCreatedEvent(IamGroup g) {
    eventPublisher
      .publishEvent(new GroupCreatedEvent(this, g, "Group created with name " + g.getName()));
  }

  @Override
  public String groupManagerAuthority(IamGroup g) {

    checkNotNull(g);
    checkNotNull(g.getUuid());

    return String.format(GROUP_MANAGER_AUTHORITY_TEMPLATE, g.getUuid());
  }

  private void groupRemovedEvent(IamGroup g) {
    eventPublisher.publishEvent(
        new GroupRemovedEvent(this, g, String.format("Group %s has been removed", g.getName())));
  }

  private void groupReplacedEvent(IamGroup oldGroup, IamGroup newGroup) {
    eventPublisher.publishEvent(new GroupReplacedEvent(this, newGroup, oldGroup, String
      .format("Replaced group %s with new group %s", oldGroup.getName(), newGroup.getName())));
  }

  private void labelSetEvent(IamGroup group, IamLabel label) {
    eventPublisher.publishEvent(new GroupLabelSetEvent(this, group, label));
  }
  
  private void labelRemovedEvent(IamGroup group, IamLabel label) {
    eventPublisher.publishEvent(new GroupLabelRemovedEvent(this, group, label));
  }
  
  private Supplier<NoSuchGroupError> noSuchGroupException(String message) {
    return () -> new NoSuchGroupError(message);
  }

  @Override
  public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
    this.eventPublisher = applicationEventPublisher;

  }

  @Override
  public IamGroup updateGroup(IamGroup oldGroup, IamGroup newGroup) {

    newGroup.setId(oldGroup.getId());
    newGroup.setUuid(oldGroup.getUuid());
    newGroup.setCreationTime(oldGroup.getCreationTime());

    newGroup.setDescription(oldGroup.getDescription());
    newGroup.setParentGroup(oldGroup.getParentGroup());
    newGroup.setChildrenGroups(oldGroup.getChildrenGroups());

    newGroup.touch(clock);

    groupReplacedEvent(oldGroup, newGroup);
    groupRepo.save(newGroup);

    return newGroup;
  }

  @Override
  public Optional<IamGroup> findByName(String name) {

    return groupRepo.findByName(name);
  }

  @Override
  public void touchGroup(IamGroup g) {
    checkNotNull(g);
    g.touch(clock);
  }

  @Override
  public IamGroup save(IamGroup g) {
    return groupRepo.save(g);
  }

  @Override
  public Optional<IamGroup> findByNameWithDifferentId(String name, String uuid) {
    return groupRepo.findByNameWithDifferentId(name, uuid);
  }

  @Override
  public long countAllGroups() {
    return groupRepo.count();
  }

  @Override
  public Page<IamGroup> findAll(Pageable page) {
    return groupRepo.findAll(page);
  }

  @Override
  public IamGroup addLabel(IamGroup g, IamLabel l) {
    
    g.getLabels().remove(l);
    g.getLabels().add(l);
    
    touchGroup(g);

    groupRepo.save(g);
    
    labelSetEvent(g, l);
    return g;
  }

  @Override
  public IamGroup deleteLabel(IamGroup g, IamLabel l) {
    g.getLabels().remove(l);
    
    labelRemovedEvent(g, l);
    touchGroup(g);
    groupRepo.save(g);
    return g;
  }

  @Override
  public Page<IamGroup> findSubgroups(IamGroup group, Pageable page) {
    return groupRepo.findSubgroups(group, page);
  }

  @Override
  public IamGroup setDescription(IamGroup g, String description) {
    g.setDescription(description);
    touchGroup(g);
    return groupRepo.save(g);
  }

}
