package it.infn.mw.iam.core.oauth.scope;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;

@RestController
public class IamOpaController {

  @Autowired
  private OpaProperties opaProperties;

  public String evaluatePolicy(@RequestBody Object payload) throws JsonMappingException, JsonProcessingException {
      
      RestTemplate restTemplate = new RestTemplate();
      
      String opaUrl = opaProperties.getUrl();
      ResponseEntity<String> response = restTemplate.postForEntity(opaUrl, payload, String.class);
      System.out.println(response);
      
      if (response.getStatusCode() == HttpStatus.OK) {
          return response.getBody();
      } else {
          return "Failed to retrieve response";
      }
  }

}
