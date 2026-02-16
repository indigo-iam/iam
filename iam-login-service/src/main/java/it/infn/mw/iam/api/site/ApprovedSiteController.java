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
package it.infn.mw.iam.api.site;

import java.util.Collection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.core.oauth.approvedsite.ApprovedSiteService;
import it.infn.mw.iam.core.web.view.HttpCodeView;
import it.infn.mw.iam.core.web.view.JsonApprovedSiteView;
import it.infn.mw.iam.core.web.view.JsonEntityView;
import it.infn.mw.iam.core.web.view.JsonErrorView;
import it.infn.mw.iam.persistence.model.ApprovedSite;
import it.infn.mw.iam.persistence.model.IamAccount;

@Controller
public class ApprovedSiteController {

  private static final Logger logger = LoggerFactory.getLogger(ApprovedSiteController.class);

  private final ApprovedSiteService approvedSiteService;
  private final AccountUtils accountUtils;

  public ApprovedSiteController(ApprovedSiteService approvedSiteService,
      AccountUtils accountUtils) {

    this.approvedSiteService = approvedSiteService;
    this.accountUtils = accountUtils;
  }

  @GetMapping(value = "/api/approved", produces = MediaType.APPLICATION_JSON_VALUE)
  @PreAuthorize("hasRole('ROLE_USER')")
  public String getAllApprovedSites(ModelMap m, Authentication a) {

    IamAccount account = accountUtils.getAuthenticatedUserAccount(a).orElseThrow();
    Collection<ApprovedSite> all = approvedSiteService.getByUser(account);
    m.put(JsonEntityView.ENTITY, all);
    return JsonApprovedSiteView.VIEWNAME;
  }

  @DeleteMapping(value = "/api/approved/{id}")
  @PreAuthorize("hasRole('ROLE_USER')")
  public String deleteApprovedSite(@PathVariable Long id, ModelMap m, Authentication a) {

    IamAccount account = accountUtils.getAuthenticatedUserAccount(a).orElseThrow();

    ApprovedSite approvedSite = approvedSiteService.getById(id);
    if (approvedSite == null) {
      logger.error("deleteApprovedSite failed; no approved site found for id: " + id);
      m.put(HttpCodeView.CODE, HttpStatus.NOT_FOUND);
      m.put(JsonErrorView.ERROR_MESSAGE,
          "Could not delete approved site. The requested approved site with id: " + id
              + " could not be found.");
      return JsonErrorView.VIEWNAME;
    } else if (!approvedSite.getAccount().equals(account)) {
      logger.error("deleteApprovedSite failed; principal " + account.getUsername()
          + " does not own approved site" + id);
      m.put(HttpCodeView.CODE, HttpStatus.FORBIDDEN);
      m.put(JsonErrorView.ERROR_MESSAGE,
          "You do not have permission to delete this approved site. The approved site decision will not be deleted.");
      return JsonErrorView.VIEWNAME;
    } else {
      m.put(HttpCodeView.CODE, HttpStatus.OK);
      approvedSiteService.remove(approvedSite);
    }
    return HttpCodeView.VIEWNAME;
  }

  @GetMapping(value = "/api/approved/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
  @PreAuthorize("hasRole('ROLE_USER')")
  public String getApprovedSite(@PathVariable Long id, ModelMap m, Authentication a) {

    IamAccount account = accountUtils.getAuthenticatedUserAccount(a).orElseThrow();

    ApprovedSite approvedSite = approvedSiteService.getById(id);
    if (approvedSite == null) {
      logger.error("getApprovedSite failed; no approved site found for id: " + id);
      m.put(HttpCodeView.CODE, HttpStatus.NOT_FOUND);
      m.put(JsonErrorView.ERROR_MESSAGE,
          "The requested approved site with id: " + id + " could not be found.");
      return JsonErrorView.VIEWNAME;
    } else if (!approvedSite.getAccount().equals(account)) {
      logger.error(
          "getApprovedSite failed; principal " + account.getUsername() + " does not own approved site" + id);
      m.put(HttpCodeView.CODE, HttpStatus.FORBIDDEN);
      m.put(JsonErrorView.ERROR_MESSAGE, "You do not have permission to view this approved site.");
      return JsonErrorView.VIEWNAME;
    } else {
      m.put(JsonEntityView.ENTITY, approvedSite);
      return JsonApprovedSiteView.VIEWNAME;
    }
  }
}
