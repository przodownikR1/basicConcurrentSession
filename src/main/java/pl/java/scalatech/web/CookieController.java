package pl.java.scalatech.web;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class CookieController {
    @RequestMapping("/cookie")
    public String hello(@CookieValue("JSESSIONID") String jsession) {
         return jsession;
    }
    
    @RequestMapping(value="/cookie/name/{name}/value/{value}",method=RequestMethod.POST)
    private ResponseEntity<?> cookieSet(@PathVariable("name") String name,  @PathVariable("value") String value, HttpServletResponse response) {

            response.addCookie(new Cookie(name, value));

            return  (ResponseEntity<?>) ResponseEntity.ok();
    }
      
}
