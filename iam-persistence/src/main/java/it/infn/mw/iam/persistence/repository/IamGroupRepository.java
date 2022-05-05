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
package it.infn.mw.iam.persistence.repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;

import it.infn.mw.iam.persistence.model.IamGroup;

public interface IamGroupRepository extends PagingAndSortingRepository<IamGroup, Long> {

  Optional<IamGroup> findByUuid(@Param("uuid") String uuid);

  Optional<IamGroup> findByName(@Param("name") String name);

  @Query("select g from IamGroup g where g.name = :name and g.uuid != :uuid")
  Optional<IamGroup> findByNameWithDifferentId(@Param("name") String name,
      @Param("uuid") String uuid);

  @Query("select g from IamGroup g where g.parentGroup is null")
  List<IamGroup> findRootGroups();

  @Query("select g from IamGroup g where g.parentGroup = :parentGroup order by g.name ASC")
  Page<IamGroup> findSubgroups(@Param("parentGroup") IamGroup parentGroup, Pageable op);

  List<IamGroup> findByNameIgnoreCaseContaining(String name);

  @Query("select g from IamGroup g where g.uuid not in :uuids")
  List<IamGroup> findByUuidNotIn(Set<String> uuids);

  Page<IamGroup> findByNameIgnoreCaseContainingOrUuidIgnoreCaseContaining(
      @Param("name") String name, @Param("uuid") String uuid, Pageable op);

  long countByNameIgnoreCaseContainingOrUuidIgnoreCaseContaining(@Param("name") String name,
      @Param("uuid") String uuid);

  @Query("select g from IamGroup g join g.labels label where label.prefix is null and label.name = :name")
  Page<IamGroup> findByLabelName(@Param("name") String name, Pageable op);

  @Query("select g from IamGroup g join g.labels label where label.prefix is null and label.name = :name and label.value = :value")
  Page<IamGroup> findByLabelNameAndValue(@Param("name") String name, @Param("value") String value,
      Pageable op);

  @Query("select m.group from IamAccountGroupMembership m where m.account.uuid = :accountUuid order by m.group.name ASC")
  Page<IamGroup> findGroupsByMemberAccountUuid(@Param("accountUuid") String accountUuid,
      Pageable op);

  @Query("select m.group from IamAccountGroupMembership m where m.account.username = :username order by m.group.name ASC")
  Page<IamGroup> findGroupsByMemberAccountUsername(@Param("username") String username, Pageable op);

  @Query("select m.group from IamAccountGroupMembership m where m.account.uuid = :accountUuid and m.group.uuid = :groupUuid")
  Optional<IamGroup> findGroupByMemberAccountUuidAndGroupUuid(
      @Param("accountUuid") String accountUuid, @Param("groupUuid") String groupUuid);

  @Query("select count(m) from IamAccountGroupMembership m where m.group.uuid= :groupUuid")
  Long countGroupMembersByGroupUuid(@Param("groupUuid") String groupUuid);


  @Query("select g from IamGroup g where g not in (select m.group from IamAccountGroupMembership m where m.account.uuid = :accountUuid) order by g.name ASC")
  Page<IamGroup> findUnsubscribedGroupsForAccount(@Param("accountUuid") String accountUuid,
      Pageable op);


  @Query("select g from IamGroup g where lower(g.name) LIKE lower(concat('%', :groupName, '%')) and g not in (select m.group from IamAccountGroupMembership m where m.account.uuid = :accountUuid) order by g.name ASC")
  Page<IamGroup> findUnsubscribedGroupsForAccountWithNameLike(
      @Param("accountUuid") String accountUuid, @Param("groupName") String groupName, Pageable op);

}
