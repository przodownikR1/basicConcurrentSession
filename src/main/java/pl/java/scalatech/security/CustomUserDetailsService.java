package pl.java.scalatech.security;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.openid.OpenIDAttribute;
import org.springframework.security.openid.OpenIDAuthenticationToken;

import com.google.inject.internal.Lists;

import lombok.extern.slf4j.Slf4j;
import pl.java.scalatech.annotation.SecurityComponent;
import pl.java.scalatech.entity.Role;
import pl.java.scalatech.entity.User;
import pl.java.scalatech.repository.UserRepository;

@SecurityComponent
@Slf4j
public class CustomUserDetailsService implements AuthenticationUserDetailsService<OpenIDAuthenticationToken>, UserDetailsService {
    @Autowired
    private UserRepository userRepository;
    private static final List<GrantedAuthority> DEFAULT_AUTHORITIES = AuthorityUtils.createAuthorityList("ROLE_USER");

    @Override
    public UserDetails loadUserDetails(OpenIDAuthenticationToken token) {
        String id = token.getIdentityUrl();

        String email = null;
        String firstName = null;
        String lastName = null;
        String fullName = null;

        List<OpenIDAttribute> attributes = token.getAttributes();

        for (OpenIDAttribute attribute : attributes) {
            switch (attribute.getName()) {
                case "email":
                    email = attribute.getValues().get(0);
                    break;
                case "firstname":
                    firstName = attribute.getValues().get(0);
                    break;
                case "lastname":
                    lastName = attribute.getValues().get(0);
                    break;
                case "fullname":
                    fullName = attribute.getValues().get(0);
                    break;
            }
        }

        if (fullName == null) {
            StringBuilder fullNameBldr = new StringBuilder();

            if (firstName != null) {
                fullNameBldr.append(firstName);
            }

            if (lastName != null) {
                fullNameBldr.append(" ").append(lastName);
            }
            fullName = fullNameBldr.toString();
        }

        log.info("email = {}",email);
        log.info("first = {}",firstName);
        log.info("last = {}",lastName);
        log.info("fullName = {}",fullName);


        id  = email.substring(0, email.indexOf('@'));
        log.info("++++++++++++++++ id : {}  , email {} ",id,email);
        User user = userRepository.findByLogin(id).orElseThrow(() -> new IllegalArgumentException("user not exists ..."));

        if (user != null) { return new UserSec(user); }

        user = User.builder().login(id).roles(Lists.newArrayList(new Role("ROLE_USER", "ordinary user"))).build();
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setFullName(fullName);
        return new UserSec(userRepository.save(user));
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return new UserSec(userRepository.findByLogin(username).orElseThrow(() -> new UsernameNotFoundException("login.not.exitst")));
    }

}