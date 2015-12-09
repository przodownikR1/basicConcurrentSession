package pl.java.scalatech.security;

import static java.util.stream.Collectors.toList;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.ToString;
import pl.java.scalatech.entity.User;
@ToString
public class UserSec implements UserDetails{

    private static final long serialVersionUID = -7740193848174002889L;
    private final User user;

    public UserSec(User user) {
       this.user = user;
    }

    @Override
     public Collection<GrantedAuthority> getAuthorities() {
        return user.getRoles().stream().map(a -> new SimpleGrantedAuthority(a.getName())).collect(toList());
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getLogin();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return user.isEnabled();
    }

}
