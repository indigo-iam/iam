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
package it.infn.mw.iam.persistence.model;

import java.io.Serializable;
import java.time.LocalDateTime;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;

@Entity
@Table(name = "translation_rule")
public class TranslationRuleEntity implements Serializable {

  private static final long serialVersionUID = 1L;

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "issuer", length = 512)
  private String issuer;

  @Column(name = "resource_server_id", length = 250)
  private String resourceServerId;

  @Enumerated(EnumType.STRING)
  @Column(name = "operation", nullable = false, length = 32)
  private TranslationOperation operation;

  @Column(name = "rule_config", nullable = false, columnDefinition = "TEXT")
  private String ruleConfig;

  @Column(name = "execution_order", nullable = false)
  private Integer executionOrder;

  @Column(name = "created_at", nullable = false, updatable = false)
  private LocalDateTime createdAt;

  @Column(name = "updated_at", nullable = false)
  private LocalDateTime updatedAt;

  public TranslationRuleEntity() {
    // empty constructor
  }

  @PrePersist
  protected void onCreate() {
    LocalDateTime now = LocalDateTime.now();
    this.createdAt = now;
    this.updatedAt = now;
  }

  @PreUpdate
  protected void onUpdate() {
    this.updatedAt = LocalDateTime.now();
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public String getIssuer() {
    return issuer;
  }

  public void setIssuer(String issuer) {
    this.issuer = issuer;
  }

  public String getResourceServerId() {
    return resourceServerId;
  }

  public void setResourceServerId(String resourceServerId) {
    this.resourceServerId = resourceServerId;
  }

  public TranslationOperation getOperation() {
    return operation;
  }

  public void setOperation(TranslationOperation operation) {
    this.operation = operation;
  }

  public String getRuleConfig() {
    return ruleConfig;
  }

  public void setRuleConfig(String ruleConfig) {
    this.ruleConfig = ruleConfig;
  }

  public Integer getExecutionOrder() {
    return executionOrder;
  }

  public void setExecutionOrder(Integer executionOrder) {
    this.executionOrder = executionOrder;
  }

  public LocalDateTime getCreatedAt() {
    return createdAt;
  }

  public LocalDateTime getUpdatedAt() {
    return updatedAt;
  }
}
