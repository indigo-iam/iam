package it.infn.mw.iam.core.time;

import org.springframework.stereotype.Component;

/**
 * 
 * A {@link TimeProvider} implementation that leverages {@link System#currentTimeMillis()} to return
 * the time.
 *
 */
@Component
public class SystemTimeProvider implements TimeProvider {

  public SystemTimeProvider() {}

  @Override
  public long currentTimeMillis() {

    return System.currentTimeMillis();
  }

}
