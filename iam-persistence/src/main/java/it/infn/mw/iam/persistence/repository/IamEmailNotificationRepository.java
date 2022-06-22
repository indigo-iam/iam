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

import javax.persistence.LockModeType;

import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;

import it.infn.mw.iam.core.IamDeliveryStatus;
import it.infn.mw.iam.core.IamNotificationType;
import it.infn.mw.iam.persistence.model.IamEmailNotification;

public interface IamEmailNotificationRepository
    extends PagingAndSortingRepository<IamEmailNotification, Long> {

  @Lock(LockModeType.PESSIMISTIC_WRITE)
  List<IamEmailNotification> findByDeliveryStatus(IamDeliveryStatus deliveryStatus);

  @Query("select n from IamEmailNotification n where n.deliveryStatus = :delivery_status and n.lastUpdate < :last_update")
  List<IamEmailNotification> findByStatusWithUpdateTime(
      @Param("delivery_status") IamDeliveryStatus deliveryStatus,
      @Param("last_update") Date lastUpdate);

  @Query("select count(n) from IamEmailNotification n")
  Integer countAllMessages();

  Integer countByDeliveryStatus(IamDeliveryStatus deliveryStatus);

  List<IamEmailNotification> findByNotificationType(IamNotificationType notificationType);
}
