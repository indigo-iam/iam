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
package it.infn.mw.iam.api.account.find;

import static it.infn.mw.iam.api.common.PagingUtils.buildPageRequest;
import static it.infn.mw.iam.api.utils.ValidationErrorUtils.handleValidationError;
import static java.util.Objects.isNull;
import static org.springframework.web.bind.annotation.RequestMethod.GET;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import com.nimbusds.jose.shaded.json.JSONObject;

import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.error.NoSuchAccountError;
import it.infn.mw.iam.api.common.form.PaginatedRequestWithFilterForm;
import it.infn.mw.iam.api.scim.model.ScimConstants;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.persistence.model.IamAccount;

@RestController
@PreAuthorize("#iam.hasScope('iam:admin.read') or #iam.hasDashboardRole('ROLE_ADMIN')")
public class FindAccountController {

  public static final String INVALID_FIND_ACCOUNT_REQUEST = "Invalid find account request";

  public static final String FIND_BY_LABEL_RESOURCE = "/iam/account/find/bylabel";
  public static final String FIND_BY_EMAIL_RESOURCE = "/iam/account/find/byemail";
  public static final String FIND_BY_USERNAME_RESOURCE = "/iam/account/find/byusername";
  public static final String FIND_BY_UUID_RESOURCE = "/iam/account/find/byuuid/{accountUuid}";
  public static final String FIND_BY_CERT_SUBJECT_RESOURCE = "/iam/account/find/bycertsubject";
  public static final String FIND_BY_GROUP_RESOURCE = "/iam/account/find/bygroup/{groupUuid}";
  public static final String FIND_NOT_IN_GROUP_RESOURCE =
      "/iam/account/find/notingroup/{groupUuid}";

  final FindAccountService service;

  @Autowired
  public FindAccountController(FindAccountService service) {
    this.service = service;
  }

  @RequestMapping(method = GET, value = FIND_BY_LABEL_RESOURCE,
      produces = ScimConstants.SCIM_CONTENT_TYPE)
  public ListResponseDTO<ScimUser> findByLabel(@RequestParam(required = true) String name,
      @RequestParam(required = false) String value,
      @RequestParam(required = false) final Integer count,
      @RequestParam(required = false) final Integer startIndex) {

    return service.findAccountByLabel(name, value, buildPageRequest(count, startIndex, 100));
  }

  @RequestMapping(method = GET, value = FIND_BY_EMAIL_RESOURCE,
      produces = ScimConstants.SCIM_CONTENT_TYPE)
  public ListResponseDTO<ScimUser> findByEmail(@RequestParam(required = true) String email) {
    return service.findAccountByEmail(email);
  }

  @RequestMapping(method = GET, value = FIND_BY_USERNAME_RESOURCE,
      produces = ScimConstants.SCIM_CONTENT_TYPE)
  public ListResponseDTO<ScimUser> findByUsername(@RequestParam(required = true) String username) {
    return service.findAccountByUsername(username);
  }

  @RequestMapping(method = GET, value = FIND_BY_CERT_SUBJECT_RESOURCE,
      produces = ScimConstants.SCIM_CONTENT_TYPE)
  public ListResponseDTO<ScimUser> findByCertSubject(
      @RequestParam(required = true) String certificateSubject) {
    return service.findAccountByCertificateSubject(certificateSubject);
  }


  @RequestMapping(method = GET, value = FIND_BY_GROUP_RESOURCE,
      produces = ScimConstants.SCIM_CONTENT_TYPE)
  public ListResponseDTO<ScimUser> findByGroup(@PathVariable String groupUuid,
      @Validated PaginatedRequestWithFilterForm form,
      BindingResult formValidationResult) {


    handleValidationError(INVALID_FIND_ACCOUNT_REQUEST, formValidationResult);

    Pageable pr = buildPageRequest(form.getCount(), form.getStartIndex(), 100);

    if (isNull(form.getFilter())) {
      return service.findAccountByGroupUuid(groupUuid, pr);
    } else {
      return service.findAccountByGroupUuidWithFilter(groupUuid, form.getFilter(), pr);
    }
  }


  @RequestMapping(method = GET, value = FIND_NOT_IN_GROUP_RESOURCE,
      produces = ScimConstants.SCIM_CONTENT_TYPE)
  public ListResponseDTO<ScimUser> findNotInGroup(@PathVariable String groupUuid,
      @Validated PaginatedRequestWithFilterForm form, BindingResult formValidationResult) {

    handleValidationError(INVALID_FIND_ACCOUNT_REQUEST, formValidationResult);

    Pageable pr = buildPageRequest(form.getCount(), form.getStartIndex(), 100);

    if (isNull(form.getFilter())) {
      return service.findAccountNotInGroup(groupUuid, pr);
    } else {
      return service.findAccountNotInGroupWithFilter(groupUuid, form.getFilter(), pr);
    }
  }

  @GetMapping(FIND_BY_UUID_RESOURCE)
  public JSONObject findByUuid(@PathVariable String accountUuid) {
    if(service.findAccountByUuid(accountUuid).isPresent()){
      IamAccount iamAccount = service.findAccountByUuid(accountUuid).get();
      return getIamAccountJson(iamAccount);
    } else{
      throw NoSuchAccountError.forUuid(accountUuid);
    }    
  }

  @ResponseStatus(value = HttpStatus.NOT_FOUND)
  @ExceptionHandler(NoSuchAccountError.class)
  public ErrorDTO accountNotFoundError(HttpServletRequest req, Exception ex) {
    return ErrorDTO.fromString(ex.getMessage());
  }

  private JSONObject getIamAccountJson(IamAccount iamAccount) {
    JSONObject iamAccountJson = new JSONObject();
    iamAccountJson.put("id", iamAccount.getId());
    iamAccountJson.put("accountUuid", iamAccount.getUuid());
    iamAccountJson.put("username", iamAccount.getUsername());
    iamAccountJson.put("active", iamAccount.isActive());
    return iamAccountJson;
  }
}
