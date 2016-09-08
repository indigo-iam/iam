package it.infn.mw.iam.notification;

import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "notification")
public class NotificationProperties {

  private Boolean disable;
  private String mailFrom;
  private long taskDelay;
  private Integer cleanupAge;
  private String adminAddress;
  private Map<String, String> subject;

  public Boolean getDisable() {
    return disable;
  }

  public void setDisable(Boolean disable) {
    this.disable = disable;
  }

  public String getMailFrom() {
    return mailFrom;
  }

  public void setMailFrom(String mailFrom) {
    this.mailFrom = mailFrom;
  }

  public long getTaskDelay() {
    return taskDelay;
  }

  public void setTaskDelay(long taskDelay) {
    this.taskDelay = taskDelay;
  }

  public Integer getCleanupAge() {
    return cleanupAge;
  }

  public void setCleanupAge(Integer cleanupAge) {
    this.cleanupAge = cleanupAge;
  }

  public String getAdminAddress() {
    return adminAddress;
  }

  public void setAdminAddress(String adminAddress) {
    this.adminAddress = adminAddress;
  }

  public Map<String, String> getSubject() {
    return subject;
  }

  public void setSubject(Map<String, String> subject) {
    this.subject = subject;
  }

}
