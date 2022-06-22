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
package it.infn.mw.iam.api.utils;

import java.util.ArrayList;
import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import it.infn.mw.iam.api.scim.converter.Converter;
import it.infn.mw.iam.api.scim.model.ScimListResponse;
import it.infn.mw.iam.api.scim.model.ScimListResponse.ScimListResponseBuilder;

public class FindUtils {

  private FindUtils() {}

  public static <D, E> ScimListResponse<D> responseFromPage(Page<E> results,
      Converter<D, E> converter,
      Pageable pageable) {
    ScimListResponseBuilder<D> builder = ScimListResponse.builder();
    List<D> resources = new ArrayList<>();

    results.getContent().forEach(a -> resources.add(converter.dtoFromEntity(a)));

    builder.resources(resources);
    builder.fromPage(results, pageable);

    return builder.build();
  }



}
