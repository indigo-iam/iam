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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.infn.mw.iam.api.scim.updater.util.NullSafeNotEqualsMatcher;

public abstract class DefaultUpdater<T> implements Updater {

  public static final Logger LOG = LoggerFactory.getLogger(DefaultUpdater.class);

  final UpdaterType type;
  final T newValue;
  final Consumer<T> setter;
  final Predicate<T> applyIf;


  public DefaultUpdater(UpdaterType type, Consumer<T> consumer, T newVal,
      Predicate<T> predicate) {

    this.type = type;
    this.newValue = newVal;
    this.setter = consumer;
    this.applyIf = predicate;

  }

  public DefaultUpdater(UpdaterType type, Supplier<T> supplier, Consumer<T> consumer, T newVal) {
    this(type, consumer, newVal, nullSafeNotEqualsMatcher(supplier));

  }

  @Override
  public boolean update() {

    if (applyIf.test(newValue)) {
      beforeUpdate();
      LOG.debug("{} applied for value '{}'", type, newValue);
      setter.accept(newValue);
      afterUpdate();
      return true;
    }

    LOG.debug("{} not applied for value '{}'", type, newValue);
    return false;
  }

  private static <T> NullSafeNotEqualsMatcher<T> nullSafeNotEqualsMatcher(Supplier<T> supp) {
    return new NullSafeNotEqualsMatcher<>(supp);
  }

  @Override
  public UpdaterType getType() {
    return type;
  }

  @Override
  public void beforeUpdate() {
  }

  @Override
  public void afterUpdate() {
  }
}
