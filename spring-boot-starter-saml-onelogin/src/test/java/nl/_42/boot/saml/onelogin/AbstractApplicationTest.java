package nl._42.boot.saml.onelogin;

import nl._42.boot.application.Application;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@SpringBootTest(classes = Application.class)
@RunWith(SpringRunner.class)
public abstract class AbstractApplicationTest {
}
