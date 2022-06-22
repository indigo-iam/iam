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

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Predicate;

import it.infn.mw.iam.persistence.model.IamAccount;

public class IdNotBoundChecker<T> implements Predicate<T> {

  final IamAccount account;
  final AccountFinder<T> finder;
  final BiConsumer<T, IamAccount> action;


  public IdNotBoundChecker(AccountFinder<T> finder, IamAccount account,
      BiConsumer<T, IamAccount> action) {

    this.finder = finder;
    this.account = account;
    this.action = action;
  }


  @Override
  public boolean test(T id) {
    checkNotNull(id);

    Optional<IamAccount> a = finder.find(id);
    
    a.ifPresent(otherAccount -> {
      if (!otherAccount.equals(account)) {
        action.accept(id, account);
      }
    });

    return true;
  }
}
