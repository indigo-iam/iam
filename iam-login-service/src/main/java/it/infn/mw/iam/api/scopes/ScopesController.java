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
package it.infn.mw.iam.api.scopes;

import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.google.gson.Gson;

import it.infn.mw.iam.core.oauth.scope.SystemScopeService;
import it.infn.mw.iam.core.web.view.HttpCodeView;
import it.infn.mw.iam.core.web.view.JsonEntityView;
import it.infn.mw.iam.core.web.view.JsonErrorView;
import it.infn.mw.iam.persistence.model.SystemScope;

@Controller
@RequestMapping("/api/scopes")
@PreAuthorize("hasRole('ROLE_USER')")
public class ScopesController {

  private static final Logger logger = LoggerFactory.getLogger(ScopesController.class);

  private final SystemScopeService scopeService;
  private final Gson gson = new Gson();

  public ScopesController(SystemScopeService scopeService) {
    this.scopeService = scopeService;
  }

  @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
  public String getAll(ModelMap m) {

    Set<SystemScope> allScopes = scopeService.getAll();
    m.put(JsonEntityView.ENTITY, allScopes);
    return JsonEntityView.VIEWNAME;
  }

  @GetMapping(value = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
  public String getScope(@PathVariable Long id, ModelMap m) {

    SystemScope scope = scopeService.getById(id);

    if (scope != null) {
      m.put(JsonEntityView.ENTITY, scope);
      return JsonEntityView.VIEWNAME;
    }

    logger.error("getScope failed; scope not found: " + id);

    m.put(HttpCodeView.CODE, HttpStatus.NOT_FOUND);
    m.put(JsonErrorView.ERROR_MESSAGE,
        "The requested scope with id " + id + " could not be found.");
    return JsonErrorView.VIEWNAME;
  }

  @PreAuthorize("hasRole('ROLE_ADMIN')")
  @PutMapping(value = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE,
      consumes = MediaType.APPLICATION_JSON_VALUE)
  public String updateScope(@PathVariable Long id, @RequestBody String json, ModelMap m) {

    SystemScope existing = scopeService.getById(id);

    SystemScope scope = gson.fromJson(json, SystemScope.class);

    if (existing != null && scope != null) {

      if (existing.getId().equals(scope.getId())) {

        scope = scopeService.save(scope);
        m.put(JsonEntityView.ENTITY, scope);
        return JsonEntityView.VIEWNAME;
      }

      logger.error("updateScope failed; scope ids to not match: got " + existing.getId() + " and "
          + scope.getId());

      m.put(HttpCodeView.CODE, HttpStatus.BAD_REQUEST);
      m.put(JsonErrorView.ERROR_MESSAGE, "Could not update scope. Scope ids to not match: got "
          + existing.getId() + " and " + scope.getId());
      return JsonErrorView.VIEWNAME;
    }

    logger.error("updateScope failed; scope with id " + id + " not found.");
    m.put(HttpCodeView.CODE, HttpStatus.NOT_FOUND);
    m.put(JsonErrorView.ERROR_MESSAGE,
        "Could not update scope. The scope with id " + id + " could not be found.");
    return JsonErrorView.VIEWNAME;
  }

  @PreAuthorize("hasRole('ROLE_ADMIN')")
  @PostMapping(value = "", produces = MediaType.APPLICATION_JSON_VALUE,
      consumes = MediaType.APPLICATION_JSON_VALUE)
  public String createScope(@RequestBody String json, ModelMap m) {

    SystemScope scope = gson.fromJson(json, SystemScope.class);

    SystemScope alreadyExists = scopeService.getByValue(scope.getValue());
    if (alreadyExists != null) {
      // Error, cannot save a scope with the same value as an existing one
      logger.error("Error: attempting to save a scope with a value that already exists: "
          + scope.getValue());
      m.put(HttpCodeView.CODE, HttpStatus.CONFLICT);
      m.put(JsonErrorView.ERROR_MESSAGE, "A scope with value " + scope.getValue()
          + " already exists, please choose a different value.");
      return JsonErrorView.VIEWNAME;
    }

    scope = scopeService.save(scope);

    if (scope != null && scope.getId() != null) {

      m.put(JsonEntityView.ENTITY, scope);

      return JsonEntityView.VIEWNAME;
    }

    logger.error("createScope failed; JSON was invalid: " + json);
    m.put(HttpCodeView.CODE, HttpStatus.BAD_REQUEST);
    m.put(JsonErrorView.ERROR_MESSAGE, "Could not save new scope " + scope
        + ". The scope service failed to return a saved entity.");
    return JsonErrorView.VIEWNAME;

  }

  @PreAuthorize("hasRole('ROLE_ADMIN')")
  @DeleteMapping(value = "/{id}")
  public String deleteScope(@PathVariable Long id, ModelMap m) {
    SystemScope existing = scopeService.getById(id);

    if (existing != null) {
      scopeService.remove(existing);
      return HttpCodeView.VIEWNAME;
    }

    logger.error("deleteScope failed; scope with id " + id + " not found.");
    m.put(HttpCodeView.CODE, HttpStatus.NOT_FOUND);
    m.put(JsonErrorView.ERROR_MESSAGE,
        "Could not delete scope. The requested scope with id " + id + " could not be found.");
    return JsonErrorView.VIEWNAME;
  }
}
