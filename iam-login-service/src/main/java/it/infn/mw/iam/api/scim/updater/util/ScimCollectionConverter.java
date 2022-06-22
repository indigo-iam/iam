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
package it.infn.mw.iam.api.scim.updater.util;

import java.util.Collection;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class ScimCollectionConverter<EntityType, ScimType>
    implements Supplier<Collection<EntityType>> {

  final Supplier<Collection<ScimType>> supplier;
  final ScimToEntity<ScimType, EntityType> converter;

  public ScimCollectionConverter(Supplier<Collection<ScimType>> supplier,
      ScimToEntity<ScimType, EntityType> converter) {

    this.supplier = supplier;
    this.converter = converter;
  }

  @Override
  public Collection<EntityType> get() {

    if (supplier.get() == null) {
      return null;
    }

    return supplier.get()
      .stream()
      .filter(Objects::nonNull)
      .map(converter::fromScim)
      .collect(Collectors.toList());
  }

}
