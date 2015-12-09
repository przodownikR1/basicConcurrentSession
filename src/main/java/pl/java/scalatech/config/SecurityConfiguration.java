package pl.java.scalatech.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import lombok.extern.slf4j.Slf4j;

@Configuration
@Slf4j
@EnableWebSecurity(debug=false)
@ComponentScan(basePackages = "pl.java.scalatech.security")
public class SecurityConfiguration extends GlobalAuthenticationConfigurerAdapter{
    private static final int MAX_SESSIONS = 1;
    @Value("${logout.url}")
    private String logoutUrl;

    @Bean
    public static HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    public static SessionRegistry getSessionRegistry() {
        return new SessionRegistryImpl();
    }
    
    @Configuration
    @Order(1)                                                        
    public static class ApiWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {
       
        protected void configure(HttpSecurity http) throws Exception {
            log.info("LOGIN RESTful  ++++++++++++  ");
            // @formatter:off            
            http.antMatcher("/api/**").authorizeRequests().anyRequest().hasRole("ADMIN")
            .and().httpBasic().and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
            http.csrf().disable();      
            
            // @formatter:on         
        }
    }
    
    @Configuration
    @Order(2)                                                        
    public static class FormLoginWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
        @Override
        public void configure(WebSecurity web) throws Exception {
            log.info("LOGIN FORM  .......");
            // @formatter:off
            web.ignoring().antMatchers("/assets/**").antMatchers("/resources/**").antMatchers("/favicon.ico").antMatchers("/webjars/**");
            // @formatter:on
        }

        @Autowired
        SessionRegistry sessionRegistry;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // http.requiresChannel().anyRequest().requiresSecure();
           // http.sessionManagement().sessionFixation().none();
            http.sessionManagement().sessionFixation().migrateSession();
            
            http.sessionManagement().invalidSessionUrl("/login?invalid=true").maximumSessions(MAX_SESSIONS).maxSessionsPreventsLogin(true).expiredUrl("/login?expired=true")
            .sessionRegistry(sessionRegistry);
            
            // @formatter:off
            http.csrf().disable().headers().disable().authorizeRequests()
            .antMatchers("/login","/loginUser", "/logout",  "/principal", "/health", "/console")
                    .permitAll()
                    .antMatchers("secContext").hasAnyRole("USER")
                    .antMatchers("/user/sessions/").hasAnyRole("USER","ADMIN")
                    .antMatchers("/user/** ").hasAnyRole("USER","ADMIN")
                    .antMatchers("/simple/**").hasAnyRole("USER")
                    .and().authorizeRequests().anyRequest().authenticated()
                    .and().formLogin()
                    .loginPage("/login").defaultSuccessUrl("/user/sessions/").failureUrl("/login?error=true").permitAll()
                    .and().logout().logoutSuccessUrl("/user/sessions/").deleteCookies("JSESSIONID").invalidateHttpSession(true);
            // @formatter:on
        }
    }
    
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth, PasswordEncoder passwordEncoder) throws Exception {
        log.info("password Encoding {}", passwordEncoder);
        // @formatter:off
        auth.inMemoryAuthentication().passwordEncoder(passwordEncoder)
        .withUser("przodownik").password("$2a$10$vGdVdtvx9jGTVs1uuywXyOiYovelvWWUFBIMbS5pSNuWmcCZlx.86").roles("USER").and()
        .withUser("aga").password("$2a$10$vGdVdtvx9jGTVs1uuywXyOiYovelvWWUFBIMbS5pSNuWmcCZlx.86").roles("BUSINESS").and()
        .withUser("vava").password("$2a$10$vGdVdtvx9jGTVs1uuywXyOiYovelvWWUFBIMbS5pSNuWmcCZlx.86").roles("USER").and()
        .withUser("bak").password("$2a$10$vGdVdtvx9jGTVs1uuywXyOiYovelvWWUFBIMbS5pSNuWmcCZlx.86").roles("USER", "ADMIN");
        // @formatter:on
    }

}
