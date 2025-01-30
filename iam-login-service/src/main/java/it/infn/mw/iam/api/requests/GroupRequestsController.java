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
package it.infn.mw.iam.api.requests;

import javax.validation.constraints.NotEmpty;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.api.common.PagingUtils;
import it.infn.mw.iam.api.requests.model.GroupRequestDto;
import it.infn.mw.iam.api.requests.service.GroupRequestsService;

@RestController
public class GroupRequestsController {

  private static final String BASE_RESOURCE = "/iam/group_requests";
  private static final Integer GROUP_REQUEST_MAX_PAGE_SIZE = 10;

  @Autowired
  private GroupRequestsService groupRequestService;

  @PreAuthorize("hasRole('USER')")
  @PostMapping(value = BASE_RESOURCE)
  public GroupRequestDto createGroupRequest(@RequestBody @Validated GroupRequestDto groupRequest) {
    return groupRequestService.createGroupRequest(groupRequest);
  }

  @PreAuthorize("hasRole('USER')")
  @GetMapping(value = BASE_RESOURCE)
  public ListResponseDTO<GroupRequestDto> listAllGroupRequests(
      @RequestParam(required = false) String username,
      @RequestParam(required = false) String groupName,
      @RequestParam(required = false) String status, @RequestParam(required = false) Integer count,
      @RequestParam(required = false) Integer startIndex) {

    final Sort sort = Sort.by("account.username", "group.name", "creationTime");

    OffsetPageable pageRequest =
        PagingUtils.buildPageRequest(count, startIndex, GROUP_REQUEST_MAX_PAGE_SIZE, sort);

    return groupRequestService.listGroupRequests(username, groupName, status, pageRequest);
  }

  @GetMapping(value = BASE_RESOURCE + "/{requestId}")
  @PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasDashboardRole('ROLE_ADMIN') or #iam.canAccessGroupRequest(#requestId)")
  public GroupRequestDto getGroupRequestDetails(@PathVariable("requestId") String requestId) {
    return groupRequestService.getGroupRequestDetails(requestId);
  }

  @DeleteMapping(value = BASE_RESOURCE + "/{requestId}")
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN') or #iam.userCanDeleteGroupRequest(#requestId)")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void deleteGroupRequest(@PathVariable("requestId") String requestId) {
    groupRequestService.deleteGroupRequest(requestId);
  }

  @PostMapping(value = BASE_RESOURCE + "/{requestId}/approve")
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN') or #iam.canManageGroupRequest(#requestId)")
  @ResponseStatus(HttpStatus.OK)
  public GroupRequestDto approveGroupRequest(@PathVariable("requestId") String requestId) {
    return groupRequestService.approveGroupRequest(requestId);
  }

  @PostMapping(value = BASE_RESOURCE + "/{requestId}/reject")
  @PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasDashboardRole('ROLE_ADMIN') or #iam.canManageGroupRequest(#requestId)")
  @ResponseStatus(HttpStatus.OK)
  public GroupRequestDto rejectGroupRequest(@PathVariable("requestId") String requestId,
      @RequestParam @NotEmpty String motivation) {
    return groupRequestService.rejectGroupRequest(requestId, motivation);
  }

}
