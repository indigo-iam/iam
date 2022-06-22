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
package it.infn.mw.iam.api.scim.updater;

import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.function.Supplier;

import org.springframework.context.ApplicationEventPublisher;

import it.infn.mw.iam.audit.events.account.AccountEvent;
import it.infn.mw.iam.persistence.model.IamAccount;

public class DefaultAccountUpdater<T, E extends AccountEvent> extends DefaultUpdater<T>
    implements AccountUpdater {

  private final IamAccount account;
  private final AccountEventBuilder<T, E> eventBuilder;

  public DefaultAccountUpdater(IamAccount account, UpdaterType type, Supplier<T> supplier,
      Consumer<T> consumer, T newVal, AccountEventBuilder<T, E> eventBuilder) {
    super(type, supplier, consumer, newVal);
    this.account = account;
    this.eventBuilder = eventBuilder;
  }

  public DefaultAccountUpdater(IamAccount account, UpdaterType type, Consumer<T> consumer, T newVal,
      Predicate<T> predicate, AccountEventBuilder<T, E> eventBuilder) {
    super(type, consumer, newVal, predicate);
    this.account = account;
    this.eventBuilder = eventBuilder;
  }

  @Override
  public IamAccount getAccount() {
    return this.account;
  }

  @Override
  public void publishUpdateEvent(Object source, ApplicationEventPublisher publisher) {

    if (eventBuilder != null) {
      publisher.publishEvent(eventBuilder.buildEvent(source, account, newValue));
    }
  }

  @Override
  public String toString() {

    return type.name();
  }
}
