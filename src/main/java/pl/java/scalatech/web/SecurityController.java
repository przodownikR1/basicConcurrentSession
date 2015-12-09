package pl.java.scalatech.web;

import static org.springframework.security.core.context.SecurityContextHolder.getContext;

import java.security.Principal;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import lombok.extern.slf4j.Slf4j;
import pl.java.scalatech.annotation.CurrentUser;
import pl.java.scalatech.entity.User;
import pl.java.scalatech.repository.UserRepository;
import pl.java.scalatech.security.UserSec;

@Controller
@Slf4j
public class SecurityController {
    @Autowired
    private UserRepository userRepository;
    
    // Error page
    @RequestMapping("/error.html")
    public String error(HttpServletRequest request, Model model) {
        model.addAttribute("errorCode", request.getAttribute("javax.servlet.error.status_code"));
        Throwable throwable = (Throwable) request.getAttribute("javax.servlet.error.exception");
        String errorMessage = null;
        if (throwable != null) {
            errorMessage = throwable.getMessage();
        }
        model.addAttribute("errorMessage", errorMessage.toString());
        return "error.html";
    }

    @RequestMapping("/currentUser")
    public ResponseEntity<User> currentUser(@CurrentUser User user) {
        return new ResponseEntity<>(user, HttpStatus.OK);
    }

    @RequestMapping("secContext")
    public ResponseEntity<Map<String, Object>> secContext(Model model) {
        SecurityContext context = getContext();
        Authentication authentication = context.getAuthentication();

        model.addAttribute("principal", authentication.getName());
        model.addAttribute("credential",authentication.getCredentials());
        model.addAttribute("authorities",authentication.getAuthorities());
        model.addAttribute("details",authentication.getDetails());
        return new ResponseEntity<>(model.asMap(), HttpStatus.OK);

    }

    @RequestMapping("/principal")
    public ResponseEntity<String> principal(Principal principal) {

        Authentication auth = getContext().getAuthentication();
        log.info("++++    {}",auth.getAuthorities());

        return new ResponseEntity<>(principal.getName(), HttpStatus.OK);

    }
    @RequestMapping("/csrf")
    public CsrfToken csrf(CsrfToken token) {
        return token;
    }
    @RequestMapping("/curUser")
    public ResponseEntity<UserSec> getCurrentUser()
    {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof UserDetails)
        {
            String username = ((UserDetails) principal).getUsername();
            Optional<User> loginUser = userRepository.findByLogin(username);
            if(loginUser.isPresent()){
                return ResponseEntity.ok(new UserSec(loginUser.get()));
            }
            
        }

        return null;
    }

}
