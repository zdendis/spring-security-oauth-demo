package dt.sdp.cornholio.springsecurityoauthdemo.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ArticlesController {
//    @Autowired
//    private WebClient webClient;

    @GetMapping("/")
    public String index(@AuthenticationPrincipal Jwt jwt) {
        return String.format("Hello, %s!", jwt.getSubject());
    }

    @GetMapping("/articles")
    public String message() {
        return "secret articles";
    }

    @PostMapping("/articles")
    public String createMessage(@RequestBody String message) {
        return String.format("Message was created. Content: %s", message);
    }

    // Client test call
//    @GetMapping(value = "/test")
//    public String[] test() {
//        return this.webClient
//                .get()
//                .uri("http://127.0.0.1:9000/articles")
//                .attributes(clientRegistrationId("articles-client"))
//                .retrieve()
//                .bodyToMono(String[].class)
//                .block();
//    }

}