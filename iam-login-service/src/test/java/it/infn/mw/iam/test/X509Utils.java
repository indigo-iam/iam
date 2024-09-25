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
package it.infn.mw.iam.test;

import java.util.ArrayList;
import java.util.List;

public class X509Utils {

  public static final List<X509Cert> x509Certs = new ArrayList<X509Cert>();

  static {

    X509Cert x509Cert = new X509Cert();
    x509Cert.display = "Personal Certificate (Test 0)";
    x509Cert.certificate = new StringBuilder("-----BEGIN CERTIFICATE-----\n")
      .append("MIIDnjCCAoagAwIBAgIBCDANBgkqhkiG9w0BAQUFADAtMQswCQYDVQQGEwJJVDEM\n")
      .append("MAoGA1UECgwDSUdJMRAwDgYDVQQDDAdUZXN0IENBMB4XDTIyMTAwMTEzMTYzMloX\n")
      .append("DTMyMDkyODEzMTYzMlowKzELMAkGA1UEBhMCSVQxDDAKBgNVBAoMA0lHSTEOMAwG\n")
      .append("A1UEAwwFdGVzdDAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCoyIIN\n")
      .append("H7YaqKMIW4kI41E0gDqtaQKYKdCv1cDL9/ibg0QLO/hyak9u9zQnp7XlK6e9NwnM\n")
      .append("T3efn3o5xWyA4nY8UWvXQRxQjuQO1hxManxFxzVHYYkd5p4JDy3lrDSPgw8yojPZ\n")
      .append("iAwVcDWZfVzXEC/EEAtbheSZcydQaEWSCLmY9rrriyvxrIlYaiAzXFhV0hRsxPy9\n")
      .append("Fk85nq1JVzeAN7jVt3JVrDgHd17IQIySXz3JU7UYChGcW3CO4LNe4p39cbjW6wbi\n")
      .append("Uqo+7caSJsOxwoS2RcHAahgd+BGegMkr48krmojuDcYrrkAL4AK0Uh5xXdWul1kG\n")
      .append("0SFf0WyN23CjuFEXAgMBAAGjgcowgccwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU\n")
      .append("aognKvxLiK8OSA1F/9x+7qCDtuUwDgYDVR0PAQH/BAQDAgXgMD4GA1UdJQQ3MDUG\n")
      .append("CCsGAQUFBwMBBggrBgEFBQcDAgYKKwYBBAGCNwoDAwYJYIZIAYb4QgQBBggrBgEF\n")
      .append("BQcDBDAfBgNVHSMEGDAWgBRQm290AeMaA1er2dV9FWRMJfP49DAnBgNVHREEIDAe\n")
      .append("gRxhbmRyZWEuY2VjY2FudGlAY25hZi5pbmZuLml0MA0GCSqGSIb3DQEBBQUAA4IB\n")
      .append("AQBHBk5Pcr3EXJZedPeEQuXCdPMDAJpAcZTCTINfGRoQXDYQk6ce8bH8jHPmao6d\n")
      .append("qV/f/14y2Jmkz+aiFQhSSyDLk4ywTgGHT+kpWEsYGbN4AdcMlH1L9uaG7YbuAZzH\n")
      .append("6bkd8HLsTiwslXYHjyldbQL9ZU6DrGAdt/IuAfFrQjWWuJ21SfBlnp4OkWQK5wTk\n")
      .append("sTvfeZX6VwinpXzF6xIrtAfJ7OYRDuN7UIrwBl9G0hoQPuXFJeVRAzYRwDVbejSo\n")
      .append("/8OWCj17EXDO+tG6Md+JYIsqJ4wrytd4YeuYDVDzbVV8DHfMrk2+PeJ0nSOSyYV+\n")
      .append("doaFzJ6837vw8+5gxDTHT/un\n")
      .append("-----END CERTIFICATE-----")
      .toString();
    x509Certs.add(x509Cert);

    x509Cert = new X509Cert();
    x509Cert.display = "Personal Certificate (Test 1)";
    x509Cert.certificate = new StringBuilder("-----BEGIN CERTIFICATE-----\n")
      .append("MIIDnjCCAoagAwIBAgIBCTANBgkqhkiG9w0BAQUFADAtMQswCQYDVQQGEwJJVDEM\n")
      .append("MAoGA1UECgwDSUdJMRAwDgYDVQQDDAdUZXN0IENBMB4XDTIyMTAwMTEzMTYzOFoX\n")
      .append("DTMyMDkyODEzMTYzOFowKzELMAkGA1UEBhMCSVQxDDAKBgNVBAoMA0lHSTEOMAwG\n")
      .append("A1UEAwwFdGVzdDEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDmIxiB\n")
      .append("Aj3Ef5DkgoFbfvNBYPbLPrPVrVr1XGdL9AeLJuL+V92NK6VOowJpufAVXSsdFAVy\n")
      .append("heKyAwhjH9w0rKng1ZAUZ4C3INX4pWOhc3FvopgzV9fahyf0JmAZETYaR8ep7MKN\n")
      .append("gG0oy42A+700aFdyydiLX2C8MxTjh3CmSQUuRoGiNVlOViJBOrlnth+0GMgzi3c4\n")
      .append("JYrwmZcA+LdkemKvqzTTAdZL/fxL/InSlx5UYZc1StBguPJ/vvKZwqSe6AnEhw3s\n")
      .append("JvftjWk0x0fSEA8NIntdoTWGDZsjnSq6DXFCUG2INA4tXeKpooX+adgy82YqedRc\n")
      .append("rEHwVD5APovNjfbZAgMBAAGjgcowgccwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU\n")
      .append("nZH4DUjNyM/w3vPUMeXQuK+AGvcwDgYDVR0PAQH/BAQDAgXgMD4GA1UdJQQ3MDUG\n")
      .append("CCsGAQUFBwMBBggrBgEFBQcDAgYKKwYBBAGCNwoDAwYJYIZIAYb4QgQBBggrBgEF\n")
      .append("BQcDBDAfBgNVHSMEGDAWgBRQm290AeMaA1er2dV9FWRMJfP49DAnBgNVHREEIDAe\n")
      .append("gRxhbmRyZWEuY2VjY2FudGlAY25hZi5pbmZuLml0MA0GCSqGSIb3DQEBBQUAA4IB\n")
      .append("AQAy8jczeHrZ/J4GQvVYAUU+3xrZB3QDW01aBBJB1d0MrUiuBysaStcRZUw2DjLK\n")
      .append("7qzp56fOxRnU6f1xAHwupSAT8+H2zlsQHZWtH/mj5i1Nj90e3BTpb4+J/rZHaz7D\n")
      .append("cm9zk16/fJtSPd6csM1eKUS/phmCI4DYTAFuTWjAa89tuZuBHAkTh6sdsVImV6RW\n")
      .append("5gktixZTpaG08uVH1WmL1iWZQyfuJObZVxSMj3S9Qnkbfr2FuvkyYRco6zMJ6hLZ\n")
      .append("KywaHrbwmPxHrC15np4bWL4HKQIyjDLzhDLLsS4xHc9bihoeXcjtUnzNVBUFeswe\n")
      .append("ZS8vKNAuv2EmVHmWBQPYKZD5\n")
      .append("-----END CERTIFICATE-----\n")
      .toString();
    x509Certs.add(x509Cert);
  }

}
