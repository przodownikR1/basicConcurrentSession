package pl.java.scalatech.entity;

import javax.persistence.Column;
import javax.persistence.Entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;


@Entity
@Data
@EqualsAndHashCode(callSuper=true)
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Role extends PKEntity {

    private static final long serialVersionUID = -804077594557972107L;
    private String name;
    @Column(name = "roleDesc")
    private String desc;
}
