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
package it.infn.mw.iam.test.repository;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.in;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.mockito.internal.util.collections.Sets;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.data.domain.Page;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.transaction.annotation.Transactional;

import com.google.common.collect.Lists;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;

@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.NONE)
@Transactional
class IamGroupRepositoryTests {

  static final String TEST_001_GROUP_ID = "c617d586-54e6-411d-8e38-649677980001";

  @Autowired
  IamGroupRepository groupRepository;

  IamGroup parent;
  IamGroup child;

  @Test
  void createParentGroup() {

    parent = createGroup(null);

    IamGroup group = groupRepository.findByUuid(parent.getUuid()).get();
    assertNotNull(group);
    assertNull(group.getParentGroup());
    assertThat(group.getChildrenGroups(), empty());
  }

  @Test
  void createNestedGroup() {

    parent = createGroup(null);
    child = createGroup(parent);

    IamGroup group = groupRepository.findByUuid(child.getUuid()).get();
    assertNotNull(group.getParentGroup());
    assertEquals(parent.getUuid(), group.getParentGroup().getUuid());

    group = groupRepository.findByUuid(parent.getUuid()).get();
    assertThat(group.getChildrenGroups(), not(empty()));
    assertThat(child, is(in(group.getChildrenGroups())));
  }

  @Test
  void deleteNestedGroup() {

    parent = createGroup(null);
    child = createGroup(parent);

    IamGroup group = groupRepository.findByUuid(child.getUuid()).get();
    groupRepository.delete(group);
    parent.getChildrenGroups().remove(child);

    groupRepository.save(parent);

    group = groupRepository.findByUuid(parent.getUuid()).get();
    assertThat(group.getChildrenGroups(), empty());
  }

  @Test
  void deleteNotEmptyParentGroup() {
    parent = createGroup(null);
    child = createGroup(parent);

    try {
      groupRepository.delete(parent);
    } catch (Exception e) {
      assertThat(e, instanceOf(TransactionSystemException.class));
    }
  }

  @Test
  void listAllRootGroups() {
    List<IamGroup> rootGroups = groupRepository.findRootGroups();
    int count = rootGroups.size();

    parent = createGroup(null);
    assertEquals(count + 1, groupRepository.findRootGroups().size());
  }

  @Test
  void listSubgroups() {
    parent = createGroup(null);

    Page<IamGroup> subgroups = groupRepository.findSubgroups(parent, null);
    assertThat(subgroups.getContent(), empty());

    child = createGroup(parent);
    subgroups = groupRepository.findSubgroups(parent, null);
    assertThat(subgroups.getNumberOfElements(), is(1));
  }

  @Test
  void lookupGroupsByName() {
    List<IamGroup> groups = groupRepository.findByNameIgnoreCaseContaining("00");
    assertThat(groups.isEmpty(), is(false));
    assertThat(groups.size(), is(9));

    groups = groupRepository.findByNameIgnoreCaseContaining("reuwyuhisajd");
    assertThat(groups.isEmpty(), is(true));

  }

  @Test
  void lookupGroupsByUuidNotInUuidSet() {
    List<IamGroup> allGroups = Lists.newArrayList(groupRepository.findAll());
    List<IamGroup> groups = groupRepository.findByUuidNotIn(Sets.newSet(TEST_001_GROUP_ID));
    assertThat(groups.isEmpty(), is(false));
    assertThat(groups.size(), equalTo(allGroups.size() - 1));
  }

  private IamGroup createGroup(IamGroup parentGroup) {
    String uuid = UUID.randomUUID().toString();
    IamGroup group = new IamGroup();
    group.setName(uuid);
    group.setUuid(uuid);
    group.setCreationTime(new Date());
    group.setLastUpdateTime(new Date());
    group.setParentGroup(parentGroup);
    groupRepository.save(group);

    if (parentGroup != null) {
      parentGroup.getChildrenGroups().add(group);
      groupRepository.save(parentGroup);
    }

    return group;
  }

}
