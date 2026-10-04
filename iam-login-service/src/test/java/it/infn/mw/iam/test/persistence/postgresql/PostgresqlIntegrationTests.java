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
package it.infn.mw.iam.test.persistence.postgresql;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.emptyArray;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.persistence.EntityManager;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationInfo;
import org.flywaydb.core.api.MigrationState;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import it.infn.mw.iam.IamLoginService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAup;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAupRepository;
import it.infn.mw.iam.persistence.repository.IamGroupRepository;

/**
 * Runs the IAM login service against a real PostgreSQL database, started with Testcontainers.
 * Skipped when Docker is not available.
 */
@Testcontainers(disabledWithoutDocker = true)
@ActiveProfiles({"postgresql-test"})
@SpringBootTest(classes = {IamLoginService.class}, webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@TestPropertySource(properties = {"iam.access_token.store_on_database=true"})
class PostgresqlIntegrationTests {

  @Container
  static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

  @DynamicPropertySource
  static void datasourceProperties(DynamicPropertyRegistry registry) {
    registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
    registry.add("spring.datasource.username", POSTGRES::getUsername);
    registry.add("spring.datasource.password", POSTGRES::getPassword);
  }

  @Autowired
  private Flyway flyway;

  @Autowired
  private JdbcTemplate jdbcTemplate;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private IamGroupRepository groupRepo;

  @Autowired
  private IamAupRepository aupRepo;

  @Autowired
  private EntityManager entityManager;

  @Autowired
  private MockMvc mvc;

  @Autowired
  private ObjectMapper mapper;

  @Test
  void allMigrationsAreApplied() {

    assertThat(flyway.info().pending(), emptyArray());

    for (MigrationInfo mi : flyway.info().applied()) {
      assertThat(mi.getScript(), mi.getState(), is(MigrationState.SUCCESS));
    }

    String product =
        jdbcTemplate.execute((java.sql.Connection c) -> c.getMetaData().getDatabaseProductName());
    assertThat(product, equalTo("PostgreSQL"));
  }

  @Test
  @Transactional
  void jpaUsesTheSameDatabase() {

    String version =
        String.valueOf(entityManager.createNativeQuery("SELECT version()").getSingleResult());
    assertThat(version.startsWith("PostgreSQL"), is(true));
  }

  @Test
  @Transactional
  void testDataIsLoaded() {

    IamAccount test = accountRepo.findByUsername("test")
      .orElseThrow(() -> new AssertionError("Expected test account not found"));

    assertThat(test.isActive(), is(true));
    assertThat(test.getUserInfo().getEmail(), equalTo("test@iam.test"));
    assertThat(groupRepo.findByName("Production").isPresent(), is(true));
  }

  @Test
  @Transactional
  void generatedIdsDoNotCollideWithTestData() {

    Long maxId = jdbcTemplate.queryForObject("SELECT MAX(id) FROM iam_group", Long.class);

    Date now = new Date();
    IamGroup group = new IamGroup();
    group.setName("postgresql-test-group");
    group.setUuid(UUID.randomUUID().toString());
    group.setCreationTime(now);
    group.setLastUpdateTime(now);

    group = groupRepo.save(group);
    entityManager.flush();

    assertThat(group.getId(), greaterThan(maxId));
  }

  @Test
  @Transactional
  void lobColumnsAreStoredAndRead() {

    String longText = "x".repeat(100_000);
    Date now = new Date();

    IamAup aup = new IamAup();
    aup.setName("postgresql-aup");
    aup.setText(longText);
    aup.setDescription("AUP stored on PostgreSQL");
    aup.setCreationTime(now);
    aup.setLastUpdateTime(now);
    aup.setSignatureValidityInDays(365L);
    aup.setAupRemindersInDays("30,15,1");
    aupRepo.save(aup);

    IamAup saved = aupRepo.findByName("postgresql-aup")
      .orElseThrow(() -> new AssertionError("Expected AUP not found"));
    assertThat(saved.getText(), equalTo(longText));
  }

  @Test
  void issuedAccessTokenIsStoredWithItsHash() throws Exception {

    String response = mvc
      .perform(post("/token").param("grant_type", "client_credentials")
        .with(httpBasic("client-cred", "secret")))
      .andExpect(status().isOk())
      .andReturn()
      .getResponse()
      .getContentAsString();

    JsonNode json = mapper.readTree(response);
    String accessToken = json.get("access_token").asText();
    assertThat(accessToken, notNullValue());

    List<Map<String, Object>> rows = jdbcTemplate.queryForList(
        "SELECT token_value_hash, encode(sha256(convert_to(token_value, 'UTF8')), 'hex') AS db_hash "
            + "FROM access_token WHERE token_value = ?",
        accessToken);
    assertThat(rows.size(), is(1));
    assertThat(rows.get(0).get("token_value_hash"), equalTo(rows.get(0).get("db_hash")));
  }
}
