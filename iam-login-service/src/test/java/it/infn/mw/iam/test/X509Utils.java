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
      .append("MIIEWDCCA0CgAwIBAgIDAII4MA0GCSqGSIb3DQEBCwUAMC4xCzAJBgNVBAYTAklU\n")
      .append("MQ0wCwYDVQQKEwRJTkZOMRAwDgYDVQQDEwdJTkZOIENBMB4XDTE1MDUxODEzNTQx\n")
      .append("NFoXDTE2MDUxNzEzNTQxNFowZDELMAkGA1UEBhMCSVQxDTALBgNVBAoTBElORk4x\n")
      .append("HTAbBgNVBAsTFFBlcnNvbmFsIENlcnRpZmljYXRlMQ0wCwYDVQQHEwRDTkFGMRgw\n")
      .append("FgYDVQQDEw9FbnJpY28gVmlhbmVsbG8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n")
      .append("ggEKAoIBAQDf74gCX/5D7HAKlI9u+vMy4R8uYvtZp60L401zOuDHc0sKPCq2sU8N\n")
      .append("IB8cNOC+69h+hPqbU8gcleXZ0T3KOy3NPrU7CFaOxzsCVAoDcLeKFlCMu4X1OK0V\n")
      .append("NPq7+fgJ1cVdsJ4StHl3oTtQPCoU6NNly8HJIufVjat2IgjNHdMHINs5IcxpTmE5\n")
      .append("OGae3reOfRBtqBr8UvyiTwHEEll6JpdbKjzjrcHBoOdFZTiwR18fO+B8MZLOjXSk\n")
      .append("OEG5p5K8y4UOkHQeqooKgW0tn7dvCxQfuu5TGYUmK6pwjcxzcnSE9U4abFh5/oD1\n")
      .append("PqjoCGtlvnl9nGrhAFD+qa5zq6SrgWsNAgMBAAGjggFHMIIBQzAMBgNVHRMBAf8E\n")
      .append("AjAAMA4GA1UdDwEB/wQEAwIEsDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUH\n")
      .append("AwQwPQYDVR0fBDYwNDAyoDCgLoYsaHR0cDovL3NlY3VyaXR5LmZpLmluZm4uaXQv\n")
      .append("Q0EvSU5GTkNBX2NybC5kZXIwJQYDVR0gBB4wHDAMBgorBgEEAdEjCgEHMAwGCiqG\n")
      .append("SIb3TAUCAgEwHQYDVR0OBBYEFIQEiwCbKssJqSBNMziZtu54ZQRCMFYGA1UdIwRP\n")
      .append("ME2AFNFi87N3csgu+/J5Gm83TiefE9UgoTKkMDAuMQswCQYDVQQGEwJJVDENMAsG\n")
      .append("A1UEChMESU5GTjEQMA4GA1UEAxMHSU5GTiBDQYIBADAnBgNVHREEIDAegRxlbnJp\n")
      .append("Y28udmlhbmVsbG9AY25hZi5pbmZuLml0MA0GCSqGSIb3DQEBCwUAA4IBAQBfhv9P\n")
      .append("4bYo7lVRYjHrxreKVaEyujzPZFowZPYMz0e/lPcdqh9TIoDBbhy7/PXiTVqQEniZ\n")
      .append("fU1Nso4rqBj8Qy609Y60PEFHhfLnjhvd/d+pXu6F1QTzUMwA2k7z5M+ykh7L46/z\n")
      .append("1vwvcdvCgtWZ+FedvLuKh7miTCfxEIRLcpRPggbC856BSKet7jPdkMxkUwbFa34Z\n")
      .append("qOuDQ6MvcrFA/lLgqN1c1OoE9tnf/uyOjVYq8hyXqOAhi2heE1e+s4o3/PQsaP5x\n")
      .append("LetVho/J33BExHo+hCMt1rN89DO5qU7FFijLlbmOZROacpjkPNn2V4wkd5WeX2dm\n")
      .append("b6UoBRqPsAiQL0mY\n")
      .append("-----END CERTIFICATE-----")
      .toString();
    x509Certs.add(x509Cert);

    x509Cert = new X509Cert();
    x509Cert.display = "Personal Certificate (Test 1)";
    x509Cert.certificate = new StringBuilder("-----BEGIN CERTIFICATE-----\n")
      .append("MIIDnjCCAoagAwIBAgIBCTANBgkqhkiG9w0BAQUFADAtMQswCQYDVQQGEwJJVDE\n")
      .append("MMAoGA1UECgwDSUdJMRAwDgYDVQQDDAdUZXN0IENBMB4XDTEyMDkyNjE1MzkzNF\n")
      .append("oXDTIyMDkyNDE1MzkzNFowKzELMAkGA1UEBhMCSVQxDDAKBgNVBAoTA0lHSTEOM\n")
      .append("AwGA1UEAxMFdGVzdDAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDK\n")
      .append("xtrwhoZ27SxxISjlRqWmBWB6U+N/xW2kS1uUfrQRav6auVtmtEW45J44VTi3WW6\n")
      .append("Y113RBwmS6oW+3lzyBBZVPqnhV9/VkTxLp83gGVVvHATgGgkjeTxIsOE+TkPKAo\n")
      .append("ZJ/QFcCfPh3WdZ3ANI14WYkAM9VXsSbh2okCsWGa4o6pzt3Pt1zKkyO4PW0cBkl\n")
      .append("etDImJK2vufuDVNm7Iz/y3/8pY8p3MoiwbF/PdSba7XQAxBWUJMoaleh8xy8HSR\n")
      .append("On7tF2alxoDLH4QWhp6UDn2rvOWseBqUMPXFjsUi1/rkw1oHAjMroTk5lL15GI0\n")
      .append("LGd5dTVopkKXFbTTYxSkPz1MLAgMBAAGjgcowgccwDAYDVR0TAQH/BAIwADAdBg\n")
      .append("NVHQ4EFgQUfLdB5+jO9LyWN2/VCNYgMa0jvHEwDgYDVR0PAQH/BAQDAgXgMD4GA\n")
      .append("1UdJQQ3MDUGCCsGAQUFBwMBBggrBgEFBQcDAgYKKwYBBAGCNwoDAwYJYIZIAYb4\n")
      .append("QgQBBggrBgEFBQcDBDAfBgNVHSMEGDAWgBSRdzZ7LrRp8yfqt/YIi0ojohFJxjA\n")
      .append("nBgNVHREEIDAegRxhbmRyZWEuY2VjY2FudGlAY25hZi5pbmZuLml0MA0GCSqGSI\n")
      .append("b3DQEBBQUAA4IBAQANYtWXetheSeVpCfnId9TkKyKTAp8RahNZl4XFrWWn2S9We\n")
      .append("7ACK/G7u1DebJYxd8POo8ClscoXyTO2BzHHZLxauEKIzUv7g2GehI+SckfZdjFy\n")
      .append("RXjD0+wMGwzX7MDuSL3CG2aWsYpkBnj6BMlr0P3kZEMqV5t2+2Tj0+aXppBPVwz\n")
      .append("JwRhnrSJiO5WIZAZf49YhMn61sQIrepvhrKEUR4XVorH2Bj8ek1/iLlgcmFMBOd\n")
      .append("s+PrehSRR8Gn0IjlEgC68EY6KPE+FKySuS7Ur7lTAjNdddfdAgKV6hJyST6/dx8\n")
      .append("ymIkb8nxCPnxCcT2I2NvDxcPMc/wmnMa+smNal0sJ6m\n")
      .append("-----END CERTIFICATE-----")
      .toString();
    x509Certs.add(x509Cert);
  }

}
