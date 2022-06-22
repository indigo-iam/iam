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

import static it.infn.mw.iam.core.IamGroupRequestStatus.PENDING;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import com.google.common.base.Strings;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.requests.exception.GroupRequestValidationError;
import it.infn.mw.iam.api.requests.model.GroupRequestDto;
import it.infn.mw.iam.core.IamGroupRequestStatus;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountGroupMembership;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamGroupRequest;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRequestRepository;

@Component
public class GroupRequestUtils {

  @Autowired
  private IamGroupRequestRepository groupRequestRepository;

  @Autowired
  private IamAccountRepository accoutRepository;

  @Autowired
  private AccountUtils accountUtils;

  private static final IamAuthority ROLE_ADMIN = new IamAuthority("ROLE_ADMIN");

  public Optional<IamGroupRequest> getOptionalGroupRequest(String uuid) {
    return groupRequestRepository.findByUuid(uuid);
  }

  public IamGroupRequest getGroupRequest(String requestId) {
    return groupRequestRepository.findByUuid(requestId)
      .orElseThrow(() -> new GroupRequestValidationError(
          String.format("Group request with UUID [%s] does not exist", requestId)));
  }

  public void checkRequestAlreadyExist(GroupRequestDto request) {
    
    List<IamGroupRequest> results = groupRequestRepository
      .findByUsernameAndGroup(request.getUsername(), request.getGroupName());
    
    for (IamGroupRequest r: results) {
      IamGroupRequestStatus status = r.getStatus();
      
      if (PENDING.equals(status)) {
        throw new GroupRequestValidationError(
            String.format("Group request already exists for [%s, %s]",
                request.getUsername(), request.getGroupName()));
      }
    }
  }

  public void validateRejectMotivation(String motivation) {
    String value = motivation;
    if (motivation != null) {
      value = motivation.trim();
    }

    if (Strings.isNullOrEmpty(value)) {
      throw new GroupRequestValidationError("Reject motivation cannot be empty");
    }
  }

  public void checkUserMembership(GroupRequestDto request) {
    Optional<IamAccount> userAccount = accoutRepository.findByUsername(request.getUsername());
    if (userAccount.isPresent()) {
      Optional<IamGroup> group = userAccount.get()
        .getGroups()
        .stream()
        .filter(g -> g.getGroup().getName().equals(request.getGroupName()))
        .findAny()
        .map(IamAccountGroupMembership::getGroup);

      if (group.isPresent()) {
        throw new GroupRequestValidationError(
            String.format("User [%s] is already member of the group [%s]", request.getUsername(),
                request.getGroupName()));
      }
    }
  }

  public Set<String> getManagedGroups() {
    Authentication authn = 
    SecurityContextHolder.getContext().getAuthentication();
    
    return authn
      .getAuthorities()
      .stream()
      .filter(a -> a.getAuthority().startsWith("ROLE_GM:"))
      .map(a -> a.getAuthority().substring(8))
      .collect(Collectors.toSet());

  }

  public boolean isPrivilegedUser() {
    Optional<IamAccount> userAccount = accountUtils.getAuthenticatedUserAccount();
    return userAccount.isPresent() && userAccount.get().getAuthorities().contains(ROLE_ADMIN);
  }
}
