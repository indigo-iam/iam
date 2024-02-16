package it.infn.mw.iam.core.oauth.scope;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import it.infn.mw.iam.config.OpaProperties;

@RestController
public class IamOpaController {

  @Autowired
  private OpaProperties opaProperties;

  public String evaluatePolicy(@RequestBody Object payload) {

    RestTemplate restTemplate = new RestTemplate();

    String opaUrl = opaProperties.getUrl();
    ResponseEntity<String> response = restTemplate.postForEntity(opaUrl, payload, String.class);

    if (response.getStatusCode() == HttpStatus.OK) {
      return response.getBody();
    } else {
      return "Failed to retrieve response";
    }
  }

}
