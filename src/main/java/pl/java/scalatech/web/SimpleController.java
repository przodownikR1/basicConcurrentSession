package pl.java.scalatech.web;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
@RestController
@RequestMapping("/simple")
public class SimpleController {

    @RequestMapping("/{name}")
     String sayHello(@PathVariable String name){
         return "Hello : "+name;
     }
    
}
