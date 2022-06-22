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
package it.infn.mw.iam.api.account.search;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Order;
import org.springframework.http.converter.json.MappingJacksonValue;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.common.PagedResourceService;
import it.infn.mw.iam.api.scim.converter.Converter;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.persistence.model.IamAccount;

@RestController
@Transactional
@PreAuthorize("hasRole('ADMIN') or #oauth2.hasScope('scim:read') or #iam.isAGroupManager()")
@RequestMapping(AccountSearchController.ACCOUNT_SEARCH_ENDPOINT)
public class AccountSearchController extends AbstractSearchController<ScimUser, IamAccount> {

  public static final String ACCOUNT_SEARCH_ENDPOINT = "/iam/account/search";
  public static final String DEFAULT_SORT_BY = "name";
  public static final String DEFAULT_SORT_DIRECTION = "asc";

  private static final String DEFAULT_START_INDEX_STRING = "" + DEFAULT_STARTINDEX;
  private static final String DEFAULT_ITEMS_PER_PAGE_STRING = "" + DEFAULT_ITEMS_PER_PAGE;

  private static final Set<String> INCLUDE_ATTRIBUTES =
      Collections.unmodifiableSet(new HashSet<>(Arrays.asList("id", "displayName", "meta", "name",
          "userName", "active", "emails", "photos", "groups")));

  @Autowired
  public AccountSearchController(PagedResourceService<IamAccount> service,
      Converter<ScimUser, IamAccount> converter) {

    super(service, converter);
  }

  @RequestMapping(method = RequestMethod.GET)
  public MappingJacksonValue getUsers(
      @RequestParam(required = false, defaultValue = DEFAULT_START_INDEX_STRING) int startIndex,
      @RequestParam(required = false, defaultValue = DEFAULT_ITEMS_PER_PAGE_STRING) int count,
      @RequestParam(required = false) String filter,
      @RequestParam(required = false, defaultValue = DEFAULT_SORT_BY) String sortBy,
      @RequestParam(required = false, defaultValue = DEFAULT_SORT_DIRECTION) String sortDirection) {

    return getResources(startIndex, count, filter, INCLUDE_ATTRIBUTES, sortBy, sortDirection);
  }

  @Override
  public Sort getSort(String sortBy, String sortDirection) {

    Sort.Direction direction = getSortDirection(sortDirection);

    switch (sortBy.toLowerCase()) {
      case "creation":
        return getSortByCreationTime(direction);
      case "email":
        return getSortByEmail(direction);
      default: /* case "name" and anything else */
        return getSortByName(direction);
    }
  }

  public static Sort getSortByName(Sort.Direction direction) {
    return Sort.by(new Order(direction, "userInfo.givenName").ignoreCase(),
        new Order(direction, "userInfo.familyName").ignoreCase());
  }

  public static Sort getSortByCreationTime(Sort.Direction direction) {
    return Sort.by(new Order(direction, "creationTime").ignoreCase());
  }

  public static Sort getSortByEmail(Sort.Direction direction) {
    return Sort.by(new Order(direction, "userInfo.email").ignoreCase());
  }
}
