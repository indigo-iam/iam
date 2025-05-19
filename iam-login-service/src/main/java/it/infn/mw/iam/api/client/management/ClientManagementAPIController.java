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
package it.infn.mw.iam.api.client.management;

import static it.infn.mw.iam.api.client.util.ClientSuppliers.clientNotFound;
import static it.infn.mw.iam.api.common.PagingUtils.buildPageRequest;
import static java.util.Objects.isNull;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.NO_CONTENT;

import java.text.ParseException;
import java.time.format.DateTimeFormatter;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.validation.ConstraintViolationException;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.annotation.JsonView;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.client.error.InvalidPaginationRequest;
import it.infn.mw.iam.api.client.error.NoSuchClient;
import it.infn.mw.iam.api.client.management.service.ClientManagementService;
import it.infn.mw.iam.api.client.service.ClientService;
import it.infn.mw.iam.api.client.util.ClientSuppliers;
import it.infn.mw.iam.api.common.ClientViews;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.PagingUtils;
import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.persistence.model.IamAccount;

@RestController
@RequestMapping(ClientManagementAPIController.ENDPOINT)
public class ClientManagementAPIController {

  public static final String ENDPOINT = "/iam/api/clients";

  private final ClientManagementService managementService;
  private final AccountUtils accountUtils;

  @Autowired
  private OAuth2TokenEntityService tokenService;

  @Autowired
  private ClientService clientService;

  DateTimeFormatter formatter = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

  public ClientManagementAPIController(ClientManagementService managementService,
      AccountUtils accountUtils) {
    this.managementService = managementService;
    this.accountUtils = accountUtils;
  }

  @PostMapping
  @ResponseStatus(CREATED)
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public RegisteredClientDTO saveNewClient(@RequestBody RegisteredClientDTO client)
      throws ParseException {
    return managementService.saveNewClient(client);
  }

  @JsonView({ ClientViews.ClientManagement.class })
  @GetMapping
  @PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public ListResponseDTO<RegisteredClientDTO> retrieveClients(
      @RequestParam final Optional<Integer> count, @RequestParam final Optional<Integer> startIndex,
      @RequestParam(defaultValue = "false") final boolean drOnly) {

    Pageable pageable = PagingUtils.buildPageRequest(count, startIndex, Sort.by("clientId"));

    if (drOnly) {
      return managementService.retrieveAllDynamicallyRegisteredClients(pageable);
    } else {
      return managementService.retrieveAllClients(pageable);
    }
  }

  @JsonView({ ClientViews.ClientManagement.class })
  @GetMapping("/{clientId}")
  @PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public RegisteredClientDTO retrieveClient(@PathVariable String clientId) {
    return managementService.retrieveClientByClientId(clientId)
        .orElseThrow(clientNotFound(clientId));
  }

  @GetMapping("/{clientId}/owners")
  @PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public ListResponseDTO<ScimUser> retrieveClientOwners(@PathVariable String clientId,
      @RequestParam final Optional<Integer> count,
      @RequestParam final Optional<Integer> startIndex) {

    return managementService.getClientOwners(clientId, buildPageRequest(count, startIndex));
  }

  @PostMapping("/{clientId}/owners/{accountId}")
  @ResponseStatus(CREATED)
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public void assignClientOwner(@PathVariable String clientId,
      @PathVariable final String accountId) {
    managementService.assignClientOwner(clientId, accountId);
  }

  @PostMapping("/{clientId}/rat")
  @ResponseStatus(CREATED)
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public RegisteredClientDTO rotateRegistrationAccessToken(@PathVariable String clientId) {
    return managementService.rotateRegistrationAccessToken(clientId);
  }

  @DeleteMapping("/{clientId}/owners/{accountId}")
  @ResponseStatus(NO_CONTENT)
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public void removeClientOwner(@PathVariable String clientId,
      @PathVariable final String accountId) {
    managementService.removeClientOwner(clientId, accountId);
  }

  @PutMapping("/{clientId}")
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public RegisteredClientDTO updateClient(@PathVariable String clientId,
      @RequestBody RegisteredClientDTO client) throws ParseException {
    return managementService.updateClient(clientId, client);
  }

  @PatchMapping("/{clientId}/enable")
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public void enableClient(@PathVariable String clientId) {
    Optional<IamAccount> account = accountUtils.getAuthenticatedUserAccount();
    account.ifPresent(a -> managementService.updateClientStatus(clientId, true, a.getUuid()));
  }

  @PatchMapping("/{clientId}/disable")
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public void disableClient(@PathVariable String clientId) {
    Optional<IamAccount> account = accountUtils.getAuthenticatedUserAccount();
    account.ifPresent(a -> managementService.updateClientStatus(clientId, false, a.getUuid()));
  }

  @PatchMapping("/{clientId}/revoke-refresh-tokens")
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public void revokeRefreshTokens(@PathVariable String clientId) {
    disableClient(clientId);
    ClientDetailsEntity client = clientService.findClientByClientId(clientId)
        .orElseThrow(ClientSuppliers.clientNotFound(clientId));
    tokenService.getRefreshTokensForClient(client)
        .forEach(rt -> tokenService.revokeRefreshToken(rt));
    rotateClientSecret(clientId);
    enableClient(clientId);
  }

  @PatchMapping("/{clientId}/revoke-access-tokens")
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public void revokeAccessTokens(@PathVariable String clientId, @RequestParam(required = false) String timeIssued) {
    disableClient(clientId);
    ClientDetailsEntity client = clientService.findClientByClientId(clientId)
        .orElseThrow(ClientSuppliers.clientNotFound(clientId));
    if (!isNull(timeIssued)) {
      LocalDateTime localDateTime = LocalDateTime.parse(timeIssued, formatter);
      Instant threshold = localDateTime.atZone(ZoneId.systemDefault()).toInstant();
      List<OAuth2AccessTokenEntity> accessTokens = tokenService.getAccessTokensForClient(client);
      for (OAuth2AccessTokenEntity rt : accessTokens) {
        try {
          Instant rtIssueTime = rt.getJwt().getJWTClaimsSet().getIssueTime().toInstant();
          if (rtIssueTime.isAfter(threshold)) {
            tokenService.revokeAccessToken(rt);
          }
          ;
        } catch (Exception e) {
        }
      }
      ;
    } else {
      tokenService.getAccessTokensForClient(client)
          .forEach(rt -> tokenService.revokeAccessToken(rt));
    }
    rotateClientSecret(clientId);
    enableClient(clientId);
  }

  @PostMapping("/{clientId}/secret")
  @ResponseStatus(CREATED)
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public RegisteredClientDTO rotateClientSecret(@PathVariable String clientId) {
    return managementService.generateNewClientSecret(clientId);
  }

  @DeleteMapping("/{clientId}")
  @ResponseStatus(NO_CONTENT)
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  public void deleteClient(@PathVariable String clientId) {
    managementService.deleteClientByClientId(clientId);
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(ConstraintViolationException.class)
  public ErrorDTO constraintValidationError(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(InvalidPaginationRequest.class)
  public ErrorDTO invalidPagination(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.NOT_FOUND)
  @ExceptionHandler(NoSuchClient.class)
  public ErrorDTO noSuchClient(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(ParseException.class)
  public ErrorDTO jsonMappingError(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }
}
