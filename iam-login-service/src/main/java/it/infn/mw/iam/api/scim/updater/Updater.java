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

import org.springframework.context.ApplicationEventPublisher;

/**
 * And updater attempts to update something, and returns true if that something was actually updated
 *
 */
public interface Updater {

  /**
   * The updater update logic
   * 
   * @return
   *         <ul>
   *         <li><code>true</code>, if the object was modified by the update</li>
   *         <li><code>false</code>, otherwise</li>
   *         </ul>
   */
  boolean update();

  /**
   * The updater type
   *
   * @return the updater type (see {@link UpdaterType})
   */
  UpdaterType getType();

  /**
   * Adds some logic before the update, in case update is done
   */
  void beforeUpdate();

  /**
   * Adds some logic after the update, in case update is done
   */
  void afterUpdate();

  void publishUpdateEvent(Object source, ApplicationEventPublisher publisher);
}
