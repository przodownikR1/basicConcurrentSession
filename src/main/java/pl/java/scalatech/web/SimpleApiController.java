package pl.java.scalatech.web;

import java.security.Principal;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
@RestController
@RequestMapping("/api")
public class SimpleApiController {
    @RequestMapping("/{name}")
    String sayHello(@PathVariable String name){
        return "Hello : "+name;
    }


    @RequestMapping(value = "/hello", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    String hello(Principal principal) {
        return ("Hello, " + principal.getName() + "!");
    }

}
