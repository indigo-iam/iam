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
package it.infn.mw.iam.authn.util;

import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;

public class SamlMetadataFetchTimer extends Timer implements DisposableBean {

  public static final Logger LOG = LoggerFactory.getLogger(SamlMetadataFetchTimer.class);

  private final Timer delegate;

  public SamlMetadataFetchTimer() {
    this.delegate = new Timer("metadata-fetch", Boolean.TRUE);
  }


  public int hashCode() {
    return delegate.hashCode();
  }

  public boolean equals(Object obj) {
    return delegate.equals(obj);
  }

  @Override
  public void schedule(TimerTask task, long delay) {
    delegate.schedule(task, delay);
  }

  @Override
  public void schedule(TimerTask task, Date time) {
    delegate.schedule(task, time);
  }

  @Override
  public void schedule(TimerTask task, long delay, long period) {
    delegate.schedule(task, delay, period);
  }

  public String toString() {
    return delegate.toString();
  }

  @Override
  public void schedule(TimerTask task, Date firstTime, long period) {
    delegate.schedule(task, firstTime, period);
  }

  @Override
  public void scheduleAtFixedRate(TimerTask task, long delay, long period) {
    delegate.scheduleAtFixedRate(task, delay, period);
  }

  @Override
  public void scheduleAtFixedRate(TimerTask task, Date firstTime, long period) {
    delegate.scheduleAtFixedRate(task, firstTime, period);
  }

  @Override
  public void cancel() {
    delegate.cancel();
  }

  @Override
  public int purge() {
    return delegate.purge();
  }


  @Override
  public void destroy() throws Exception {
    LOG.debug("in destroy");
    delegate.purge();
    delegate.cancel();
  }

}
