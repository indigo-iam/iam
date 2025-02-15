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
package it.infn.mw.iam.test.api.requests;

import static it.infn.mw.iam.core.IamGroupRequestStatus.APPROVED;
import static it.infn.mw.iam.core.IamGroupRequestStatus.PENDING;
import static it.infn.mw.iam.core.IamGroupRequestStatus.REJECTED;

import java.util.Date;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.api.requests.GroupRequestConverter;
import it.infn.mw.iam.api.requests.model.GroupRequestDto;
import it.infn.mw.iam.core.IamGroupRequestStatus;
import it.infn.mw.iam.persistence.model.IamGroupRequest;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRequestRepository;

public class GroupRequestsTestUtils {

  protected static final String BASE_URL = "/iam/group_requests";
  protected static final String CREATE_URL = BASE_URL;
  protected static final String LIST_ALL_REQUESTS_URL = BASE_URL;
  protected static final String GET_DETAILS_URL = BASE_URL + "/{uuid}";
  protected static final String DELETE_URL = GET_DETAILS_URL;
  protected static final String APPROVE_URL = GET_DETAILS_URL + "/approve";
  protected static final String REJECT_URL = GET_DETAILS_URL + "/reject";

  protected static final String TEST_ADMIN = "admin";
  protected static final String TEST_ADMIN_UUID = "73f16d93-2441-4a50-88ff-85360d78c6b5";
  protected static final String TEST_ADMIN_FULL_NAME = "Admin User";
  protected static final String TEST_USERNAME = "test";
  protected static final String TEST_USERUUID = "80e5fb8d-b7c8-451a-89ba-346ae278a66f";
  protected static final String TEST_100_USERNAME = "test_100";
  protected static final String TEST_100_USERUUID = "f2ce8cb2-a1db-4884-9ef0-d8842cc02b4a";
  protected static final String TEST_101_USERNAME = "test_101";
  protected static final String TEST_101_USERUUID = "1a78b3b8-22d2-4746-9269-df55aceb036f";
  protected static final String TEST_102_USERNAME = "test_102";
  protected static final String TEST_103_USERNAME = "test_103";
  protected static final String TEST_001_GROUPNAME = "Test-001";
  protected static final String TEST_002_GROUPNAME = "Test-002";
  protected static final String TEST_001_GROUP_UUID = "c617d586-54e6-411d-8e38-649677980001";
  protected static final String TEST_002_GROUP_UUID = "c617d586-54e6-411d-8e38-649677980002";

  protected static final String TEST_NOTES = "Test group request membership";
  protected static final String TEST_REJECT_MOTIVATION = "You are not welcome!";

  @Autowired
  protected IamGroupRequestRepository groupRequestRepository;

  @Autowired
  protected IamAccountRepository accountRepository;

  @Autowired
  protected IamGroupRepository groupRepository;

  @Autowired
  protected GroupRequestConverter converter;

  @Autowired
  protected ObjectMapper mapper;

  protected GroupRequestDto buildGroupRequest(String userUuid, String groupName) {
    GroupRequestDto request = new GroupRequestDto();
    request.setGroupName(groupName);
    request.setNotes(TEST_NOTES);
    request.setUserUuid(userUuid);
    return request;
  }

  protected GroupRequestDto savePendingGroupRequest(String username, String groupName) {
    return saveGroupRequest(username, groupName, PENDING);
  }

  protected GroupRequestDto saveApprovedGroupRequest(String username, String groupName) {
    return saveGroupRequest(username, groupName, APPROVED);
  }

  protected GroupRequestDto saveRejectedGroupRequest(String username, String groupName) {
    return saveGroupRequest(username, groupName, REJECTED);
  }

  private GroupRequestDto saveGroupRequest(String username, String groupName,
      IamGroupRequestStatus status) {

    IamGroupRequest iamGroupRequest = new IamGroupRequest();
    iamGroupRequest.setUuid(UUID.randomUUID().toString());
    iamGroupRequest.setAccount(accountRepository.findByUsername(username).get());
    iamGroupRequest.setGroup(groupRepository.findByName(groupName).get());
    iamGroupRequest.setNotes(TEST_NOTES);
    iamGroupRequest.setStatus(status);
    iamGroupRequest.setCreationTime(new Date());
    if (REJECTED.equals(status)) {
      iamGroupRequest.setMotivation(TEST_REJECT_MOTIVATION);
    }

    IamGroupRequest result = groupRequestRepository.save(iamGroupRequest);

    return converter.fromEntity(result);
  }
}
