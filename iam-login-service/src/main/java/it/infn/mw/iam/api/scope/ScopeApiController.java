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
package it.infn.mw.iam.api.scope;

import java.util.List;
import java.util.Optional;

import org.mitre.oauth2.model.SystemScope;
import org.mitre.oauth2.service.SystemScopeService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping(value = {"/api/scopes", "/iam/api/scopes"})
public class ScopeApiController {

  private final SystemScopeService scopeService;
  private final SystemScopeDtoConverter scopeConverter;

  public ScopeApiController(SystemScopeService scopeService,
      SystemScopeDtoConverter scopeConverter) {
    this.scopeService = scopeService;
    this.scopeConverter = scopeConverter;
  }

  @PreAuthorize("hasRole('ROLE_USER')")
  @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
  public List<SystemScopeDto> getAllScopes() {
    return scopeService.getAllSorted().stream().map(scopeConverter::dtoFromEntity).toList();
  }

  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  @PostMapping(produces = MediaType.APPLICATION_JSON_VALUE,
      consumes = MediaType.APPLICATION_JSON_VALUE)
  public SystemScopeDto create(@RequestBody SystemScopeDto dto) {
    SystemScope newScope = scopeConverter.entityFromDto(dto);
    newScope.setId(null);
    return scopeConverter.dtoFromEntity(scopeService.create(newScope));
  }

  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  @PutMapping(value = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE,
      consumes = MediaType.APPLICATION_JSON_VALUE)
  public SystemScopeDto update(@PathVariable Long id, @RequestBody SystemScopeDto dto) {
    SystemScope newScope = scopeConverter.entityFromDto(dto);
    newScope.setId(id);
    return scopeConverter.dtoFromEntity(scopeService.update(newScope));
  }

  @PreAuthorize("hasRole('ROLE_USER')")
  @GetMapping(value = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
  public SystemScopeDto getById(@PathVariable Long id) {
    Optional<SystemScope> scope = scopeService.get(id);
    if (scope.isPresent()) {
      return scopeConverter.dtoFromEntity(scope.get());
    }
    throw notFound();
  }

  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  @DeleteMapping(value = "/{id}")
  public void deleteScope(@PathVariable Long id) {
    Optional<SystemScope> scope = scopeService.get(id);
    if (scope.isPresent()) {
      scopeService.remove(scope.get());
    }
  }

  private ResponseStatusException notFound() {
    return new ResponseStatusException(HttpStatus.NOT_FOUND, "Scope value not found");
  }
}
