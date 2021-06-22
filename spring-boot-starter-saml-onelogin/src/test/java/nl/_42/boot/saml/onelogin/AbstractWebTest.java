package nl._42.boot.saml.onelogin;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;

@RunWith(MockitoJUnitRunner.class)
public abstract class AbstractWebTest {

  private final ObjectMapper objectMapper = new ObjectMapper();

  protected MockMvc webClient;

  protected void initWebClient(Object controller) {
    MappingJackson2HttpMessageConverter converter = new MappingJackson2HttpMessageConverter(objectMapper);

    this.webClient = MockMvcBuilders.standaloneSetup(controller)
      .setMessageConverters(converter)
      .setHandlerExceptionResolvers((HandlerExceptionResolver) (request, response, handler, ex) -> {
        response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        return new ModelAndView(new MappingJackson2JsonView(), "error", ex.getMessage());
      })
      .build();
  }

}
