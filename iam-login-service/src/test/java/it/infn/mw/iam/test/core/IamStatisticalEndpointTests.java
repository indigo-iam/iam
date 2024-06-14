package it.infn.mw.iam.test.core;

import static org.hamcrest.Matchers.equalTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import it.infn.mw.iam.test.util.annotation.IamMockMvcIntegrationTest;

@RunWith(SpringRunner.class)
@IamMockMvcIntegrationTest
public class IamStatisticalEndpointTests {

  @Autowired
  protected MockMvc mvc;

  @Test
  public void anonymousisAcceptedAtStatEndpoint() throws Exception {
    mvc.perform(get("/stats"))
      .andDo(print())
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.numberOfUsers", equalTo(255)));
  }

}
