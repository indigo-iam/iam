/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2023
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

import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

import org.mitre.oauth2.model.ClientDetailsEntity;

/**
 * 
 * This entity is the login-service component as it needs to "see" the ClientDetailsEntity mitreid
 * Entity, which is not accessible in the iam-persistence scope.
 * 
 *
 */
@Entity
@Table(name = "iam_client_last_used")
public class IamClientLastUsed {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false, updatable = false)
    private Long id;

    @OneToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "client_id", nullable = false, updatable = false)
    private ClientDetailsEntity client;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "last_used", nullable = false, updatable = true)
    private Date lastUsed;

    public IamClientLastUsed() {
        // emptyOnPurpose
    }

    public ClientDetailsEntity getClient() {
        return client;
    }

    public void setClient(ClientDetailsEntity client) {
        this.client = client;
    }

    public Date getLastUsed() {
        return lastUsed;
    }

    public void setLastUsed(Date lastUsed) {
        this.lastUsed = lastUsed;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((client == null) ? 0 : client.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        IamClientLastUsed other = (IamClientLastUsed) obj;
        if (client == null) {
            if (other.client != null) {
                return false;
            }
        } else if (!client.equals(other.client)) {
            return false;
        }
        return true;
    }

}
