package pl.java.scalatech.web;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import lombok.extern.slf4j.Slf4j;

@Controller
@Slf4j
public class UserSessionController {
    private final SessionRegistry sessionRegistry;

    @Autowired
    public UserSessionController(SessionRegistry sessionRegistry) {
        this.sessionRegistry = sessionRegistry;
    }

    @RequestMapping("/user/sessions/")
    public String sessions(Authentication authentication, ModelMap model) {
        List<SessionInformation> sessions = sessionRegistry.getAllSessions(authentication.getPrincipal(), false);
        log.info("+++ sessions :  {}",sessions);
        model.put("sessions", sessions);

        return "sessions";
    }

    @RequestMapping(value = "/user/sessions/{sessionId}", method = {RequestMethod.DELETE,RequestMethod.GET})
    public String removeSession(@PathVariable String sessionId, RedirectAttributes redirectAttrs) {
        SessionInformation sessionInformation = sessionRegistry.getSessionInformation(sessionId);
        if (sessionInformation != null) {
            sessionInformation.expireNow();
        }
        redirectAttrs.addFlashAttribute("message", "Session wasremoved");
        return "redirect:sessions/";
    }
}