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
package it.infn.mw.iam.test.util;

import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.subethamail.wiser.Wiser;

public class MockSmtpServerUtils {
  public static final Logger LOG = LoggerFactory.getLogger(MockSmtpServerUtils.class);

  private static void waitUntilPortIsFree(String host, int port, int timeoutInSecs) {

    boolean portBusy = true;
    int sleepTimeInSecs = 0;

    do {
      try {
        // Open a client socket to talk with iamHost at port
        (new Socket(host, port)).close();

        // If we reach this far there's someone listening,
        // i.e. the port is busy
        LOG.warn("Port {} is in use", port);

        // So sleep 1 sec
        Thread.sleep(TimeUnit.SECONDS.toMillis(1));
        sleepTimeInSecs++;
        portBusy = true;
      } catch (IOException e) {
        portBusy = false;
      } catch (InterruptedException e) {
      }
    } while (portBusy && sleepTimeInSecs < timeoutInSecs);

    if (sleepTimeInSecs >= timeoutInSecs) {
      throw new AssertionError("Timeout reached waiting for port " + port);
    }
  }

  public static synchronized Wiser startMockSmtpServer(String hostname, int port) {

    waitUntilPortIsFree(hostname, port, 5);

    LOG.info("Starting Wiser SMTP server on: {}:{}", hostname, port);

    Wiser mockSmtpServer = new Wiser();

    mockSmtpServer.setHostname(hostname);
    mockSmtpServer.setPort(port);

    mockSmtpServer.start();

    return mockSmtpServer;
  }

  public static synchronized void stopMockSmtpServer(Wiser mockSmtpServer) {

    if (mockSmtpServer != null) {
      LOG.info("Stopping Wiser SMTP server");
      mockSmtpServer.stop();
    }

  }
}
