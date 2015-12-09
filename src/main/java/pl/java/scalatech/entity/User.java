package pl.java.scalatech.entity;

import java.util.LinkedList;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Transient;

import com.fasterxml.jackson.annotation.JsonIgnore;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Entity
@Data
@EqualsAndHashCode(callSuper = true)
@NoArgsConstructor
@AllArgsConstructor
@Builder
// @PasswordsEqualConstraint
public class User extends PKEntity {
    private static final long serialVersionUID = -2181703844979860927L;

    // @NotNull
    // @Size(min = 2, max = 30)
    private String login;

    // @NotNull
    // @Size(min = 2, max = 50)
    private String lastName;

    // @NotNull
    // @Size(min = 2, max = 50)
    private String firstName;

    @Transient
    private String fullName;

    // @NotNull
    // @Min(6)
    // @Column(nullable = false, length = 20)
    @JsonIgnore
    private String password;

    @Transient
    private String confirmPassword;

    private String email;

    private boolean enabled = true;

    @ManyToMany(fetch = FetchType.EAGER, cascade = { CascadeType.ALL })
    @JoinTable(name = "USER_ROLE", joinColumns = { @JoinColumn(name = "userId") }, inverseJoinColumns = { @JoinColumn(name = "roleId") })
    // @Valid
    private List<Role> roles = new LinkedList<>();

}