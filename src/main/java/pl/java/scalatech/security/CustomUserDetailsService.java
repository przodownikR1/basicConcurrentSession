package pl.java.scalatech.security;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import lombok.extern.slf4j.Slf4j;
import pl.java.scalatech.annotation.SecurityComponent;
import pl.java.scalatech.repository.UserRepository;

@SecurityComponent
@Slf4j
public class CustomUserDetailsService implements  UserDetailsService {
    @Autowired
    private UserRepository userRepository;
    private static final List<GrantedAuthority> DEFAULT_AUTHORITIES = AuthorityUtils.createAuthorityList("ROLE_USER");

  

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return new UserSec(userRepository.findByLogin(username).orElseThrow(() -> new UsernameNotFoundException("login.not.exitst")));
    }

}