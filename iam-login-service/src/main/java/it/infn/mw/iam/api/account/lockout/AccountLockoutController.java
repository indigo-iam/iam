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
package it.infn.mw.iam.api.account.lockout;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.persistence.model.IamAccountLoginLockout;
import it.infn.mw.iam.persistence.repository.IamAccountLoginLockoutRepository;

@RestController
public class AccountLockoutController {

  private final IamAccountLoginLockoutRepository lockoutRepo;

  public AccountLockoutController(IamAccountLoginLockoutRepository lockoutRepo) {
    this.lockoutRepo = lockoutRepo;
  }

  @GetMapping("/iam/account/{uuid}/lockout")
  @PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public ResponseEntity<?> getLockoutStatus(@PathVariable String uuid) {
    Optional<IamAccountLoginLockout> lockout = lockoutRepo.findByAccountUuid(uuid);

    if (lockout.isPresent() && lockout.get().getSuspendedUntil() != null
        && System.currentTimeMillis() < lockout.get().getSuspendedUntil().getTime()) {
      return ResponseEntity.ok(Map.of(
          "suspended", true,
          "suspendedUntil", lockout.get().getSuspendedUntil().getTime()));
    }

    return ResponseEntity.ok(Map.of("suspended", false));
  }

  @GetMapping("/iam/account/lockout/suspended")
  @PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public ResponseEntity<?> getAllSuspendedUsers() {
    List<String> suspendedUsers = lockoutRepo.findAllSuspendedUsers();
    return ResponseEntity.ok(suspendedUsers);
  }
}
