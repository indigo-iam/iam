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
package it.infn.mw.iam.persistence.repository;

import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.mitre.oauth2.model.DeviceCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface IamDeviceCodeRepository extends JpaRepository<DeviceCode, Long> {

  Optional<DeviceCode> findById(String id);

  Optional<DeviceCode> findByDeviceCode(String deviceCode);

  Optional<DeviceCode> findByUserCode(String userCode);

  @Query("select dc from DeviceCode dc where dc.expiration <= :timestamp")
  List<DeviceCode> findExpired(@Param("timestamp") Date timestamp);

}
