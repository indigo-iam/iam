package it.infn.mw.iam.test.util.oidc;

import org.springframework.http.HttpEntity;
import org.springframework.util.MultiValueMap;

public class CodeRequestUtil {

  public String nonce;
  public HttpEntity<MultiValueMap<String, String>> requestEntity;

}
