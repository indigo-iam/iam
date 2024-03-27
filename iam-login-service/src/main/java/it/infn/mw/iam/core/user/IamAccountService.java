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
package it.infn.mw.iam.core.user;

import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAttribute;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamLabel;
import it.infn.mw.iam.persistence.model.IamSshKey;

/**
 * This service provides basic functionality used to manage IAM accounts
 */
public interface IamAccountService {


  /**
   * Finds an account by UUID
   * 
   * @param uuid
   * @return an {@link Optional} iam account
   */
  Optional<IamAccount> findByUuid(String uuid);

  /**
   * Creates a new {@link IamAccount}, after some checks.
   * 
   * @param account the account to be created
   * @return the created {@link IamAccount}
   */
  IamAccount createAccount(IamAccount account);


  /**
   * Triggers a save operation for the account
   * 
   * @param account the account to be saved
   * @return the updated account
   */
  IamAccount saveAccount(IamAccount account);

  /**
   * Deletes a {@link IamAccount}.
   * 
   * @param account the account to be deleted
   * 
   * @return the deleted {@link IamAccount}
   */
  IamAccount deleteAccount(IamAccount account);

  /**
   * Deletes provisioned accounts whose last login time is before than the timestamp passed as
   * argument
   * 
   * @param timestamp the timestamp
   * @return the possibly empty {@link List} of {@link IamAccount} that have been removed
   */
  List<IamAccount> deleteInactiveProvisionedUsersSinceTime(Date timestamp);

  /**
   * Sets a label for a given account
   * 
   * @param account
   * @param label
   * @return the updated account
   */
  IamAccount setLabel(IamAccount account, IamLabel label);

  /**
   * Deletes a label for a given account
   * 
   * @param account
   * @param label
   * @return the updated account
   */
  IamAccount deleteLabel(IamAccount account, IamLabel label);

  /**
   * Sets end time for a given account
   * 
   * @param account
   * @param endTime
   * @return the updated account
   */
  IamAccount setAccountEndTime(IamAccount account, Date endTime);

  /**
   * Disables account
   * 
   * @param account
   * @return the updated account
   */
  IamAccount disableAccount(IamAccount account);

  /**
   * Restores account
   * 
   * @param account
   * @return the updated account
   */
  IamAccount restoreAccount(IamAccount account);

  /**
   * Sets an attribute for the account
   * 
   * @param account
   * @param attribute
   * @return the updated account
   */
  IamAccount setAttribute(IamAccount account, IamAttribute attribute);

  /**
   * Deletes an attribute for the account
   * 
   * @param account
   * @param attribute
   * @return the updated account
   */
  IamAccount deleteAttribute(IamAccount account, IamAttribute attribute);

  /**
   * Adds an account to a group
   * 
   * @param account
   * @param group
   * @return the updated account
   */
  IamAccount addToGroup(IamAccount account, IamGroup group);

  /**
   * Removes the account from the group
   * 
   * @param account
   * @param group
   * @return the updated account
   */
  IamAccount removeFromGroup(IamAccount account, IamGroup group);

  /**
   * Returns group members
   * 
   * @param group the group
   * @param page pagination params
   * @return the page of accounts that are members of the group
   */
  Page<IamAccount> fingGroupMembers(IamGroup group, Pageable page);


  /**
   * Links an ssh key to an account
   * 
   * @param account
   * @param key
   * @return the updated account
   */
  IamAccount addSshKey(IamAccount account, IamSshKey key);

  /**
   * Removes an ssh key from an account
   * 
   * @param account
   * @param key
   * @return the updated account
   */
  IamAccount removeSshKey(IamAccount account, IamSshKey key);

}
