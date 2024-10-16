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


import javax.servlet.http.HttpServletRequest;
import javax.validation.ConstraintViolationException;
import javax.validation.Valid;

import javax.validation.constraints.NotEmpty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.api.common.PagingUtils;
import it.infn.mw.iam.api.requests.model.CertLinkRequestDTO;
import it.infn.mw.iam.api.requests.service.CertLinkRequestsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;



@RestController
@RequestMapping("/iam/cert_link_requests")
@Validated
public class CertLinkRequestsController {

  private static final Integer CERT_LINK_REQUEST_MAX_PAGE_SIZE = 10;
  public static final String INVALID_REQUEST_TEMPLATE = "Invalid request: %s";

  @Autowired
  private CertLinkRequestsService certLinkRequestService;

  @PostMapping({"", "/"})
  @PreAuthorize("hasAnyRole('ADMIN', 'USER')")
  public CertLinkRequestDTO createCertLinkRequest(
      @RequestBody @Valid CertLinkRequestDTO certLinkRequest,
      final BindingResult validationResult) {

    return certLinkRequestService.createCertLinkRequest(certLinkRequest);
  }

  @GetMapping({"", "/"})
  @PreAuthorize("hasAnyRole('ADMIN','USER')")
  public ListResponseDTO<CertLinkRequestDTO> listCertLinkRequest(
      @RequestParam(required = false) String username,
      @RequestParam(required = false) String subjectDn, @RequestParam(required = false) String status,
      @RequestParam(required = false) Integer count,
      @RequestParam(required = false) Integer startIndex) {

    final Sort sort = Sort.by("account.username", "certificate.subjectDn", "creationTime");

    OffsetPageable pageRequest =
        PagingUtils.buildPageRequest(count, startIndex, CERT_LINK_REQUEST_MAX_PAGE_SIZE, sort);

    return certLinkRequestService.listCertLinkRequests(username, subjectDn, status, pageRequest);
  }

  @GetMapping("/{requestId}")
  @PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasDashboardRole('ROLE_ADMIN') or #iam.userCanAccessCertLinkRequest(#requestId)")
  public CertLinkRequestDTO getCertLinkRequestDetails(
      @Valid @PathVariable("requestId") String requestId) {
    return certLinkRequestService.getCertLinkRequestDetails(requestId);
  }

  @DeleteMapping("/{requestId}")
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN') or #iam.userCanDeleteCertLinkRequest(#requestId)")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void deleteCertLinkRequest(@Valid @PathVariable("requestId") String requestId) {
    certLinkRequestService.deleteCertLinkRequest(requestId);
  }

  @PostMapping("/{requestId}/approve")
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  @ResponseStatus(HttpStatus.OK)
  public CertLinkRequestDTO approveCertLinkRequest(
      @Valid @PathVariable("requestId") String requestId) {
    return certLinkRequestService.approveCertLinkRequest(requestId);
  }

  @PostMapping("/{requestId}/reject")
  @PreAuthorize("#iam.hasScope('iam:admin.write') or #iam.hasDashboardRole('ROLE_ADMIN')")
  @ResponseStatus(HttpStatus.OK)
  public CertLinkRequestDTO rejectCertLinkRequest(
      @Valid @PathVariable("requestId") String requestId,
      @RequestParam @NotEmpty String motivation) {
    return certLinkRequestService.rejectCertLinkRequest(requestId, motivation);
  }

  @ResponseStatus(value = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(ConstraintViolationException.class)
  public ErrorDTO constraintValidationError(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(String.format(INVALID_REQUEST_TEMPLATE, ex.getMessage()));
  }

}
