package it.infn.mw.iam.persistence.model;

import java.time.LocalDate;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.MapsId;
import javax.persistence.OneToOne;
import javax.persistence.Table;

@Entity
@Table(name = "client_last_used")
public class IamClientLastUsed {

    @Id
    @Column(name = "client_details_id")
    private Long id;

    @OneToOne(cascade = CascadeType.ALL)
    @MapsId
    @JoinColumn(name = "client_details_id")
    private IamClient client;

    @Column(name = "last_used", nullable = false)
    private LocalDate lastUsed;

    public IamClientLastUsed() {
        // empty constructor
    }

    public IamClientLastUsed(IamClient client, LocalDate lastUsed) {
        this.client = client;
        this.lastUsed = lastUsed;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public IamClient getClient() {
        return client;
    }

    public void setClient(IamClient client) {
        this.client = client;
    }

    public LocalDate getLastUsed() {
        return lastUsed;
    }

    public void setLastUsed(LocalDate lastUsed) {
        this.lastUsed = lastUsed;
    }
}
