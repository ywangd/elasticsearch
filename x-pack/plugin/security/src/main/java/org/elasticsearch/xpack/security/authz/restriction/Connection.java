/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.security.authz.restriction;

import io.netty.handler.ipfilter.IpFilterRule;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.xpack.security.authc.pki.PkiRealm;

import java.net.InetSocketAddress;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.function.Predicate;
import javax.net.ssl.X509ExtendedTrustManager;

public class Connection {

    private final X509Certificate[] certs;
    private final InetSocketAddress remoteAddress;
    private final int port;

    private Connection(X509Certificate[] certs, InetSocketAddress remoteAddress, int port) {
        this.certs = certs;
        this.remoteAddress = remoteAddress;
        this.port = port;
    }

    public static Connection fromThreadContext(ThreadContext threadContext) {
        return new Connection(
            threadContext.getTransient(PkiRealm.PKI_CERT_HEADER_NAME),
            threadContext.getTransient("__REMOTE_ADDRESS"),
            threadContext.getTransient("__PORT"));
    }

    public static class ConnectionPredicate implements Predicate<Connection> {

        private final X509ExtendedTrustManager trustManager;
        private final int port;
        private final IpFilterRule ipFilterRule;

        public ConnectionPredicate(X509ExtendedTrustManager trustManager, int port, IpFilterRule ipFilterRule) {
            this.trustManager = trustManager;
            this.port = port;
            this.ipFilterRule = ipFilterRule;
        }

        @Override
        public boolean test(Connection connection) {
            try {
                trustManager.checkClientTrusted(connection.certs, "UNKNOWN");
            } catch (CertificateException e) {
                e.printStackTrace();
                return false;
            }
            return port == connection.port && ipFilterRule.matches(connection.remoteAddress);
        }
    }

}

