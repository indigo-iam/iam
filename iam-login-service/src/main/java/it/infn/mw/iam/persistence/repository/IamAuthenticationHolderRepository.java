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

import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface IamAuthenticationHolderRepository
    extends JpaRepository<AuthenticationHolderEntity, Long> {

  @Query("select a from AuthenticationHolderEntity a where "
      + "a.id not in (select t.authenticationHolder.id from OAuth2AccessTokenEntity t) and "
      + "a.id not in (select r.authenticationHolder.id from OAuth2RefreshTokenEntity r) and "
      + "a.id not in (select c.authenticationHolder.id from AuthorizationCodeEntity c)")
  Page<AuthenticationHolderEntity> getOrphans(Pageable op, @Param("timestamp") Date timestamp);

}
