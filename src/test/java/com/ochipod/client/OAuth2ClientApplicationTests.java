package com.ochipod.client;

import static org.junit.Assert.assertThat;

import java.net.URI;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;

/*@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
		"APP-CLIENT-ID=my-client-id", "APP-CLIENT-SECRET=my-client-secret" })*/
public class OAuth2ClientApplicationTests {
/*
	@LocalServerPort
	private int port;

	@Autowired
	private TestRestTemplate restTemplate;

	@Test
	public void everythingShouldRedirectToLogin() throws Exception {
		ResponseEntity<String> entity = this.restTemplate.getForEntity("/", String.class);
		assertThat(entity.getStatusCode()).isEqualTo(HttpStatus.FOUND);
		assertThat(entity.getHeaders().getLocation())
				.isEqualTo(URI.create("http://localhost:" + this.port + "/login"));
	}

	@Test
	public void loginShouldHaveBothOAuthClientsToChooseFrom() throws Exception {
		ResponseEntity<String> entity = this.restTemplate.getForEntity("/login",
				String.class);
		assertThat(entity.getStatusCode()).isEqualTo(HttpStatus.OK);
		assertThat(entity.getBody()).contains("/oauth2/authorization/github-client-1");
		assertThat(entity.getBody()).contains("/oauth2/authorization/github-client-2");
	}*/

}