/*
 * Copyright (c) 2017 Public Library of Science
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
package org.plos.cas.web.flow;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;

public class EnvironmentAction
{

  public static final String REGISTRATION_BASE_URL_ENV = "REGISTRATION_BASE_URL";

  private final Logger logger = LoggerFactory.getLogger(getClass());

  public EnvironmentAction() {
    logger.info("{}={}", REGISTRATION_BASE_URL_ENV, getRegistrationBaseUrl());
  }

  @Bean
  public final String getRegistrationBaseUrl() {
    String baseUrl = getenv(REGISTRATION_BASE_URL_ENV);
    if (isEmptyOrBlank(baseUrl)) {
      baseUrl = "https://localhost:4201";
    }
    return baseUrl;
  }

  @Bean
  public final String foo() { return "FOOO!!!"; }

  // relax visibility for testing
  String getenv(String name) {
    return System.getenv(name);
  }

  private boolean isEmptyOrBlank(String s) {
    return s == null || s.trim().isEmpty();
  }
}
