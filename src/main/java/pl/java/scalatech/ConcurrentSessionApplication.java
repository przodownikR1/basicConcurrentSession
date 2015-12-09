package pl.java.scalatech;

import java.util.Locale;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.embedded.ConfigurableEmbeddedServletContainer;
import org.springframework.boot.context.embedded.EmbeddedServletContainerCustomizer;
import org.springframework.boot.context.embedded.tomcat.TomcatEmbeddedServletContainerFactory;
import org.springframework.context.MessageSource;

import com.google.common.collect.Lists;

import lombok.extern.slf4j.Slf4j;
import pl.java.scalatech.entity.Role;
import pl.java.scalatech.entity.User;
import pl.java.scalatech.repository.RoleRepository;
import pl.java.scalatech.repository.UserRepository;

@SpringBootApplication
@Slf4j
public class ConcurrentSessionApplication  implements EmbeddedServletContainerCustomizer ,  CommandLineRunner {
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private MessageSource messageSource;

    public static void main(String[] args) {
        SpringApplication.run(ConcurrentSessionApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        Role user= roleRepository.save(new Role("USER","only for ordinary user"));
        Role admin= roleRepository.save(new Role("ADMIN","only for special right user"));
        log.info("+++++++++++++   {}",user.getId());

        User one = userRepository.save(User.builder().firstName("slawek").login("przodownik")
                .password("vava").enabled(true).build());
        User two = userRepository.save(User.builder().firstName("vava").login("vava")
                .password("vava").enabled(true)
                .build());
        one.setRoles(Lists.newArrayList(user,admin));
        two.setRoles(Lists.newArrayList(user));
         User oneLoaded =  userRepository.save(one);
        User twoLoaded = userRepository.save(two);
        log.info("+++ one {}",oneLoaded);
        log.info("+++ two {}",twoLoaded);

        log.info("+++++  {}",messageSource.getMessage("sess.msg.lastRequest", null, Locale.getDefault()));
        

    }
     @Override
    public void customize(final ConfigurableEmbeddedServletContainer container)
    {
        ((TomcatEmbeddedServletContainerFactory) container).addContextCustomizers(context ->{


            context.setSessionTimeout(30);
            context.setSessionCookieName("JSESSIONID");
            context.setUseHttpOnly(false);
            });
    }
}
