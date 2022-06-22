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
package it.infn.mw.voms.aa.impl;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.voms.aa.VOMSRequest;
import it.infn.mw.voms.aa.VOMSRequestContext;
import it.infn.mw.voms.aa.VOMSResponse;

public class RequestContextImpl implements VOMSRequestContext {

  public RequestContextImpl(VOMSRequest req, VOMSResponse resp) {

    request = req;
    response = resp;
    handled = false;
  }

  private IamAccount account;
  private VOMSRequest request;
  private VOMSResponse response;
  private boolean handled;

  private String host;
  private String voName;
  private int port;

  private String userAgent;

  @Override
  public VOMSRequest getRequest() {

    return request;
  }

  @Override
  public VOMSResponse getResponse() {

    return response;
  }

  @Override
  public boolean isHandled() {

    return handled;
  }

  @Override
  public void setHandled(boolean handled) {

    this.handled = handled;
  }

  @Override
  public String getVOName() {

    return voName;
  }

  @Override
  public void setVOName(String vo) {

    voName = vo;
  }

  @Override
  public String getHost() {

    return host;
  }

  @Override
  public void setHost(String hostname) {

    this.host = hostname;
  }

  @Override
  public int getPort() {

    return port;
  }

  @Override
  public void setPort(int port) {

    this.port = port;
  }

  @Override
  public IamAccount getIamAccount() {
    return account;
  }

  @Override
  public void setIamAccount(IamAccount account) {
    this.account = account;
  }

  @Override
  public String getUserAgent() {
    return userAgent;
  }

  @Override
  public void setUserAgent(String userAgent) {
    this.userAgent = userAgent;
  }

}
