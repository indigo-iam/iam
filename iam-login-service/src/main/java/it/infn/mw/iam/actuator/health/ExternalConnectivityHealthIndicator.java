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
package it.infn.mw.iam.actuator.health;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.actuate.health.Status;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.config.IamProperties;

@Component
@ConditionalOnProperty(name = "iam.external-connectivity-probe.enabled", havingValue = "true")
public class ExternalConnectivityHealthIndicator implements HealthIndicator {

  private static final String STATUS_WARNING = "WARNING";
  private static final String STATUS_WARNING_MSG = "external endpoint unreachable";
  private static final String ENDPOINT_KEY = "endpoint";

  private final String endpoint;
  private final int timeoutInSecs;

  @Autowired
  public ExternalConnectivityHealthIndicator(IamProperties properties) {
    this.endpoint = properties.getExternalConnectivityProbe().getEndpoint();
    this.timeoutInSecs = properties.getExternalConnectivityProbe().getTimeoutInSecs();
  }

  @Override
  public Health health() {
    try {
      HttpURLConnection conn = (HttpURLConnection) new URL(endpoint).openConnection();
      conn.setRequestMethod(HttpMethod.HEAD.name());
      conn.setConnectTimeout((int) TimeUnit.SECONDS.toMillis(timeoutInSecs));

      int responseCode = conn.getResponseCode();

      if (responseCode == 200) {
        return Health.up().withDetail(ENDPOINT_KEY, endpoint).build();
      } else {
        return Health.status(new Status(STATUS_WARNING, STATUS_WARNING_MSG))
          .withDetail(ENDPOINT_KEY, endpoint)
          .build();
      }
    } catch (IOException e) {
      return Health.status(new Status(STATUS_WARNING, STATUS_WARNING_MSG)).withException(e).build();
    }
  }
}
