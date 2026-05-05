package it.infn.mw.iam.core.oauth.scope.pdp;

import it.infn.mw.iam.authn.oidc.RestTemplateFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;

import it.infn.mw.iam.config.OPAProperties;

@RestController
public class IamOPAController {
    private RestTemplate restTemplate;
    private OPAProperties opaProperties;

    public IamOPAController(OPAProperties opaProperties, RestTemplateFactory restTemplateFactory) {
        this.opaProperties = opaProperties;
        this.restTemplate = restTemplateFactory.newRestTemplate();
    }

    public String evaluatePolicy(@RequestBody Object payload) throws JsonMappingException, JsonProcessingException {
        String opaHost = opaProperties.getHost();
        ResponseEntity<String> response = restTemplate.postForEntity(opaHost, payload, String.class);
        System.out.println(response);

        if (response.getStatusCode() == HttpStatus.OK) {
            return response.getBody();
        }
        else {
            return "Failed to retrieve response";
        }
    }
}
