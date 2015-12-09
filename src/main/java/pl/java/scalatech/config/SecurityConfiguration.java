package pl.java.scalatech.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import lombok.extern.slf4j.Slf4j;

@Configuration
@Slf4j
@EnableWebSecurity(debug=true)
@ComponentScan(basePackages = "pl.java.scalatech.security")
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    private static final int MAX_SESSIONS = 2;
    @Value("${logout.url}")
    private String logoutUrl;



    @Override
    public void configure(WebSecurity web) throws Exception {
        // @formatter:off
        web.ignoring().antMatchers("/assets/**").antMatchers("/resources/**").antMatchers("/favicon.ico").antMatchers("/webjars/**");
        // @formatter:on
    }

    @Autowired
    SessionRegistry sessionRegistry;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // http.requiresChannel().anyRequest().requiresSecure();

        // @formatter:off
        http.csrf().disable().headers().disable().authorizeRequests()
        .antMatchers("/login", "/logout",  "principal", "/health", "/console")
                .permitAll()
                 .antMatchers("secContext").hasAnyRole("USER")
                .antMatchers("/simple/**").hasAnyRole("USER")
                .antMatchers("/actuator/**").hasRole("ADMIN")
                .antMatchers("/metrics/**").hasRole("ADMIN")
                .antMatchers("/info/**").hasRole("ADMIN").antMatchers("/health/**").hasRole("ADMIN")
                .antMatchers("/trace/**").hasRole("ADMIN")
                .antMatchers("/dump/**").hasRole("ADMIN")
                .antMatchers("/shutdown/**").hasRole("ADMIN")
                .antMatchers("/beans/**").hasRole("ADMIN")
                .antMatchers("/env/**").hasRole("ADMIN")
                .antMatchers("/autoconfig/**").hasRole("ADMIN").anyRequest().authenticated()
                .and().formLogin()
                .loginPage("/login").defaultSuccessUrl("/user/sessions/").permitAll()
                .and().logout().logoutSuccessUrl(logoutUrl).logoutRequestMatcher(new AntPathRequestMatcher("/logout")).logoutSuccessUrl(logoutUrl);
        http.sessionManagement().invalidSessionUrl("/invalidSession").maximumSessions(MAX_SESSIONS).expiredUrl("/sessionError").maxSessionsPreventsLogin(true)
        .sessionRegistry(sessionRegistry).and().sessionFixation().migrateSession();


        // @formatter:on
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth, PasswordEncoder passwordEncoder) throws Exception {
        log.info("password Encoding {}", passwordEncoder);

        auth.inMemoryAuthentication().passwordEncoder(passwordEncoder).withUser("przodownik")
                .password("$2a$10$vGdVdtvx9jGTVs1uuywXyOiYovelvWWUFBIMbS5pSNuWmcCZlx.86").roles("USER").and().withUser("aga")
                .password("$2a$10$vGdVdtvx9jGTVs1uuywXyOiYovelvWWUFBIMbS5pSNuWmcCZlx.86").roles("BUSINESS").and().withUser("vava")
                .password("$2a$10$vGdVdtvx9jGTVs1uuywXyOiYovelvWWUFBIMbS5pSNuWmcCZlx.86").roles("USER").and().withUser("bak")
                .password("$2a$10$vGdVdtvx9jGTVs1uuywXyOiYovelvWWUFBIMbS5pSNuWmcCZlx.86").roles("USER", "ADMIN");

    }

    @Bean
    public static HttpSessionEventPublisher httpSessionEventPublisher() {
        log.info("+++++++  httpSessionEventPublisher init");
        return new HttpSessionEventPublisher();
    }

    @Bean
    public static SessionRegistry getSessionRegistry() {
        return new SessionRegistryImpl();
    }

}
