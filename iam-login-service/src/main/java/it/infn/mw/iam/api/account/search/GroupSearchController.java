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

import static it.infn.mw.iam.api.scim.model.ScimConstants.INDIGO_GROUP_SCHEMA;
import static java.util.Arrays.asList;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import it.infn.mw.iam.api.scim.model.ScimGroup;
import it.infn.mw.iam.persistence.model.IamGroup;

@RestController
@Transactional
@PreAuthorize("hasAnyRole('ADMIN', 'USER') or #oauth2.hasScope('scim:read')")
@RequestMapping(GroupSearchController.GROUP_SEARCH_ENDPOINT)
public class GroupSearchController extends AbstractSearchController<ScimGroup, IamGroup> {

  public static final Logger log = LoggerFactory.getLogger(GroupSearchController.class);

  public static final String GROUP_SEARCH_ENDPOINT = "/iam/group/search";
  public static final String DEFAULT_SORT_BY = "name";
  public static final String DEFAULT_SORT_DIRECTION = "asc";

  private static final String DEFAULT_START_INDEX_STRING = "" + DEFAULT_STARTINDEX;
  private static final String DEFAULT_ITEMS_PER_PAGE_STRING = "" + DEFAULT_ITEMS_PER_PAGE;

  static final Set<String> INCLUDED_ATTRIBUTES =
      Collections.unmodifiableSet(new HashSet<>(asList("id", "displayName", "meta", INDIGO_GROUP_SCHEMA)));

  @Autowired
  public GroupSearchController(PagedResourceService<IamGroup> service,
      Converter<ScimGroup, IamGroup> converter) {

    super(service, converter);
  }

  @RequestMapping(method = RequestMethod.GET)
  public MappingJacksonValue getGroups(
      @RequestParam(required = false, defaultValue = DEFAULT_START_INDEX_STRING) int startIndex,
      @RequestParam(required = false, defaultValue = DEFAULT_ITEMS_PER_PAGE_STRING) int count,
      @RequestParam(required = false) String filter,
      @RequestParam(required = false, defaultValue = DEFAULT_SORT_BY) String sortBy,
      @RequestParam(required = false, defaultValue = DEFAULT_SORT_DIRECTION) String sortDirection) {

    return getResources(startIndex, count, filter, INCLUDED_ATTRIBUTES, sortBy, sortDirection);
  }

  @Override
  public Sort getSort(String sortBy, String sortDirection) {

    return getSortByName(getSortDirection(sortDirection));
  }

  public static Sort getSortByName(Sort.Direction direction) {
    return Sort.by(new Order(direction, "name").ignoreCase());
  }
}
