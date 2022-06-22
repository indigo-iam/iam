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
package it.infn.mw.iam.api.scim.converter;

/**
 * 
 * Converts IAM entities to DTO objects. Design shamelessly inspired by
 * https://github.com/osiam/osiam.
 * 
 * @param <D> The DTO object type 
 * @param <E> The entity object type
 *
 * 
 */
public interface Converter<D, E> {

  /**
   * Converts a DTO object in an entity object
   * 
   * @param dto the DTO object to be converted
   * 
   * @return an Entity object
   */
  E entityFromDto(D dto);

  /**
   * Converts an IAM entity to the related DTO.
   * 
   * @param entity an entity 
   * 
   * @return a DTO representation of the entity
   */
  D dtoFromEntity(E entity);

}
