package db.migration.h2;

import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.rowset.SqlRowSet;

import it.infn.mw.iam.core.Sha256Encoder;
import it.infn.mw.iam.persistence.migrations.BaseFlywayJavaMigrationAdapter;

public class V123__HashClientSecret extends BaseFlywayJavaMigrationAdapter {

  @Override
  public void migrate(JdbcTemplate jdbcTemplate) throws DataAccessException {

    SqlRowSet clientList = jdbcTemplate.queryForRowSet(
        "SELECT id, client_secret FROM client_details WHERE client_secret IS NOT NULL");

    while (clientList.next()) {

      String clientSecret = clientList.getString("client_secret");
      String clientSecretHash = Sha256Encoder.encode(clientSecret);

      Long id = clientList.getLong("id");
      jdbcTemplate.update("UPDATE client_details SET client_secret=? WHERE id=?",
          clientSecretHash, id);
    }
  }

}
