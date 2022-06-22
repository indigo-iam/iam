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

import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.converter.json.MappingJacksonValue;

import com.fasterxml.jackson.databind.ser.FilterProvider;
import com.fasterxml.jackson.databind.ser.impl.SimpleBeanPropertyFilter;
import com.fasterxml.jackson.databind.ser.impl.SimpleFilterProvider;
import com.google.common.collect.Lists;

import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.common.OffsetPageable;
import it.infn.mw.iam.api.common.PagedResourceService;
import it.infn.mw.iam.api.scim.converter.Converter;

public abstract class AbstractSearchController<T, E> {

  public static final Logger log = LoggerFactory.getLogger(AbstractSearchController.class);

  public static final int DEFAULT_ITEMS_PER_PAGE = 10;
  public static final int DEFAULT_STARTINDEX = 1;
  public static final String DEFAULT_FILTER = "";

  private PagedResourceService<E> service;
  private Converter<T, E> converter;

  public AbstractSearchController(PagedResourceService<E> service, Converter<T, E> converter) {

    this.converter = converter;
    this.service = service;
  }

  public MappingJacksonValue getResources(int requestedStartIndex, int requestedCount, String filter, Set<String> attributes, String sortBy, String sortDirection) {

    ListResponseDTO.Builder<T> response = ListResponseDTO.builder();

    int startIndex = requestedStartIndex <= 0 ? 1 : requestedStartIndex;
    int count = requestedCount < 0 || requestedCount > DEFAULT_ITEMS_PER_PAGE ? DEFAULT_ITEMS_PER_PAGE : requestedCount;
    boolean hasFilter = filter != null && !filter.isEmpty();

    if (count == 0) {

      long totalResults;

      if (hasFilter) {

        totalResults = service.count(filter);

      } else {

        totalResults = service.count();
      }

      response.totalResults(totalResults);

    } else {

      Pageable op = new OffsetPageable(startIndex - 1, count, getSort(sortBy, sortDirection));
      Page<E> p;

      if (hasFilter) {

        p = service.getPage(op, filter);

      } else {

        p = service.getPage(op);
      }

      List<T> resources = convertFromPage(p, converter);
      response.resources(resources);
      response.fromPage(p, op);
    }

    return filterResponseAttributes(response.build(), attributes);
  }

  protected abstract Sort getSort(String sortBy, String sortDirection);

  protected Sort.Direction getSortDirection(String value) {

    try {
      return Sort.Direction.fromString(value);
    } catch (IllegalArgumentException e) {
      log.error(e.getMessage(), e);
      return Sort.Direction.ASC;
    }
  }

  protected MappingJacksonValue filterResponseAttributes(ListResponseDTO<T> response,
      Set<String> filteredAttributes) {

    MappingJacksonValue wrapper = new MappingJacksonValue(response);
    FilterProvider filterProvider = new SimpleFilterProvider().addFilter("attributeFilter",
        SimpleBeanPropertyFilter.filterOutAllExcept(filteredAttributes));
    wrapper.setFilters(filterProvider);
    return wrapper;
  }

  protected List<T> convertFromPage(Page<E> entities, Converter<T, E> converter) {

    List<T> resources = Lists.newArrayList();
    entities.getContent().forEach(e -> resources.add(converter.dtoFromEntity(e)));
    return resources;
  }
}
