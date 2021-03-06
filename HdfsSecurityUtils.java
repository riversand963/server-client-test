/*
 * The Alluxio Open Foundation licenses this work under the Apache License, version 2.0
 * (the "License"). You may not use this work except in compliance with the License, which is
 * available at www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied, as more fully set forth in the License.
 *
 * See the NOTICE file distributed with this work for information regarding copyright ownership.
 */

import org.apache.hadoop.security.UserGroupInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.PrivilegedExceptionAction;

/**
 * A utility class that allows program code to run in a security context provided by the HDFS
 * security user and groups information.
 */
public final class HdfsSecurityUtils {
  private static final Logger LOG = LoggerFactory.getLogger(HdfsSecurityUtils.class);
  private static boolean isHdfsSecurityEnabled() {
    return UserGroupInformation.isSecurityEnabled();
  }

  /**
   * Runs a method in a security context as the current user.
   *
   * @param runner the method to be run
   * @param <T> the return type
   * @return the result of the secure method
   * @throws IOException if failed to run as the current user
   */
  public static <T> T runAsCurrentUser(final SecuredRunner<T> runner) throws IOException {
    if (!isHdfsSecurityEnabled()) {
      LOG.warn("security is not enabled");
      return runner.run();
    }

    UserGroupInformation ugi = UserGroupInformation.getCurrentUser();
    return runAs(ugi, runner);
  }

  /**
   * Runs a method in a security context as the specified user.
   *
   * @param runner the method to be run
   * @param <T> the return type
   * @param ugi the specified user
   * @return the result of the secure method
   * @throws IOException if failed to run as the specified user
   */
  public static <T> T runAs(UserGroupInformation ugi, final SecuredRunner<T> runner)
      throws IOException {
    if (!isHdfsSecurityEnabled()) {
      LOG.warn("security is not enabled");
      return runner.run();
    }

    LOG.info("UGI: " + ugi.toString());
    LOG.info("UGI login user " + ugi.getLoginUser());
    LOG.info("UGI current user " + ugi.getCurrentUser());

    if (ugi.getAuthenticationMethod() == UserGroupInformation.AuthenticationMethod.KERBEROS
        && !ugi.hasKerberosCredentials()) {
      LOG.error("UFS Kerberos security is enabled but UGI has no Kerberos credentials. "
          + "Please check Alluxio configurations for Kerberos principal and keytab file.");
    }
    try {
      return ugi.doAs(new PrivilegedExceptionAction<T>() {
        @Override
        public T run() throws IOException {
          return runner.run();
        }
      });
    } catch (InterruptedException e) {
      throw new IOException(e);
    }
  }

  /**
   * Interface for specifying logic to execute securely.
   *
   * @param <T> the return type of run method
   */
  public interface SecuredRunner<T> {
    /**
     * Program logic to execute securely.
     *
     * @return an instance of {@code T}
     * @throws IOException if something went wrong
     */
    T run() throws IOException;
  }

  private HdfsSecurityUtils() {}  // prevent instantiation
}

