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
package it.infn.mw.iam.api.scope_policy;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.persistence.model.IamScopePolicy;
import it.infn.mw.iam.persistence.model.IamScopePolicy.MatchingPolicy;
import it.infn.mw.iam.persistence.model.PolicyRule;


@RestController
public class ScopePolicyController {

  private static final Logger LOG = LoggerFactory.getLogger(ScopePolicyController.class);

  private final ScopePolicyService policyService;
  private final IamScopePolicyConverter converter;

  @Autowired
  public ScopePolicyController(ScopePolicyService policyService,
      IamScopePolicyConverter converter) {
    this.policyService = policyService;
    this.converter = converter;
  }

  @RequestMapping(value = "/iam/scope_policies", method = RequestMethod.GET)
  @PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasAnyDashboardRole('ROLE_ADMIN', 'ROLE_READER')")
  public List<ScopePolicyDTO> listScopePolicies() {

    Iterable<IamScopePolicy> policies = policyService.findAllScopePolicies();
    List<ScopePolicyDTO> dtos = new ArrayList<>();

    policies.forEach(p -> dtos.add(converter.fromModel(p)));

    return dtos;
  }

  @RequestMapping(value = "/iam/scope_policies", method = RequestMethod.POST)
  @ResponseStatus(code = HttpStatus.CREATED)
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public void addScopePolicy(@Valid @RequestBody ScopePolicyDTO policy,
      BindingResult validationResult) {

    if (validationResult.hasErrors()) {
      throw buildValidationError(validationResult);
    }

    policyService.createScopePolicy(policy);
  }


  @RequestMapping(value = "/iam/scope_policies/{id}", method = RequestMethod.GET)
  @PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public ScopePolicyDTO getScopePolicy(@PathVariable Long id) {

    IamScopePolicy p = policyService.findScopePolicyById(id)
      .orElseThrow(() -> new ScopePolicyNotFoundError("No scope policy found for id: " + id));

    return converter.fromModel(p);

  }

  @RequestMapping(value = "/iam/scope_policies/{id}", method = RequestMethod.PUT)
  @ResponseStatus(code = HttpStatus.NO_CONTENT)
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public void updateScopePolicy(@PathVariable Long id, @Valid @RequestBody ScopePolicyDTO policy,
      BindingResult validationResult) {

    if (validationResult.hasErrors()) {
      throw buildValidationError(validationResult);
    }

    policy.setId(id);

    policyService.updateScopePolicy(policy);
  }

  @RequestMapping(value = "/iam/scope_policies/{id}", method = RequestMethod.DELETE)
  @ResponseStatus(code = HttpStatus.NO_CONTENT)
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public void deleteScopePolicy(@PathVariable Long id) {

    policyService.deleteScopePolicyById(id);

  }

  @GetMapping(value = "/iam/scope_policies/opa")
  @PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasAnyDashboardRole('ROLE_ADMIN', 'ROLE_READER')")
  public OpaPolicies convertToOpaPolicies() {

    Iterable<IamScopePolicy> policies = policyService.findAllScopePolicies();
    List<OpaPolicies.OpaPolicy> dtos = new ArrayList<>();

    policies.forEach(p -> {
      if (!p.getMatchingPolicy().equals(MatchingPolicy.REGEXP)) {
        dtos.add(converter.toOpaPolicyDTO(p));
      }
    });

    return new OpaPolicies(dtos);
  }

  public record OpaPolicies(List<OpaPolicy> policies) {

    public record OpaPolicy(@JsonInclude(JsonInclude.Include.NON_NULL) Actor actor,
        @JsonInclude(JsonInclude.Include.NON_EMPTY) String description,
        MatchingPolicy matchingPolicy, PolicyRule rule,
        @JsonInclude(JsonInclude.Include.NON_EMPTY) Set<String> scopes) {

      @JsonPropertyOrder({ "id", "name", "username", "type" })
      public record Actor(String id, @JsonIgnore String value, String type) {

        @JsonProperty("username")
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public String username() {
          return "account".equals(type) ? value : null;
        }

        @JsonProperty("name")
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public String name() {
          return "group".equals(type) ? value : null;
        }

      }
    }
  }

  @ResponseStatus(value = HttpStatus.NOT_FOUND)
  @ExceptionHandler(ScopePolicyNotFoundError.class)
  public ErrorDTO notFoundError(Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(InvalidScopePolicyError.class)
  public ErrorDTO validationError(Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(DuplicateScopePolicyError.class)
  public ErrorDTO duplicatePolicyError(Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(HttpMessageNotReadableException.class)
  public ErrorDTO invalidRequestBody(Exception ex) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Error parsing scope policy JSON: {}", ex.getMessage(), ex);
    }
    return ErrorDTO
      .fromString("Invalid scope policy: could not parse the policy JSON representation");
  }

  protected InvalidScopePolicyError buildValidationError(BindingResult result) {
    String firstErrorMessage = result.getAllErrors().get(0).getDefaultMessage();
    return new InvalidScopePolicyError(firstErrorMessage);
  }
}
