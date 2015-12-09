package pl.java.scalatech.entity;

import java.util.Date;

import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.FetchType;
import javax.persistence.MappedSuperclass;
import javax.persistence.PreUpdate;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

import lombok.Data;
import lombok.EqualsAndHashCode;

@MappedSuperclass
@Data
@EqualsAndHashCode(callSuper = true)
public abstract class PKEntity extends AbstactId {

    private static final long serialVersionUID = 7669211182758111346L;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "date_modification")
    @Basic(fetch = FetchType.LAZY)
    protected Date dateModification;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "date_added", nullable = false)
    protected Date dateAdded = new Date();

    @PreUpdate
    private void initPreUpdate() {
        dateModification = new Date();
        if (dateAdded == null) {
            dateAdded = dateModification;
        }
    }
}