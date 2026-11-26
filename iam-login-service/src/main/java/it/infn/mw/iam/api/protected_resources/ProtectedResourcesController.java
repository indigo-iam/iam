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
package it.infn.mw.iam.api.protected_resources;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.config.IamProperties.ProtectedResourceProperties;
import it.infn.mw.iam.core.web.wellknown.ProtectedResourceRegistry;

@RestController
public class ProtectedResourcesController {

  public static final String ENDPOINT = "/iam/api/protected-resources";

  private final ProtectedResourceRegistry registry;

  public ProtectedResourcesController(ProtectedResourceRegistry registry) {
    this.registry = registry;
  }

  @GetMapping(ENDPOINT)
  @PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public List<ProtectedResourceProperties> listProtectedResources() {
    return registry.getResources();
  }

  // Only reloads this IAM instance: see iam.protected-resources-file.check-period-secs
  @PostMapping(ENDPOINT + "/reload")
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public List<ProtectedResourceProperties> reloadProtectedResources() {
    return registry.reload();
  }

  @ResponseStatus(HttpStatus.CONFLICT)
  @ExceptionHandler(IllegalStateException.class)
  public String notReloadable(IllegalStateException e) {
    return e.getMessage();
  }

  @ResponseStatus(HttpStatus.BAD_REQUEST)
  @ExceptionHandler(IllegalArgumentException.class)
  public String invalidFile(IllegalArgumentException e) {
    return e.getMessage();
  }
}
