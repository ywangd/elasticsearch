package org.elasticsearch.xpack.core.security;

import org.apache.logging.log4j.Logger;
import org.elasticsearch.RecordJFR;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authc.support.AuthenticationContextSerializer;

import java.io.IOException;
import java.util.function.BiConsumer;

public class SecurityHelper {

//    private static final AuthenticationContextSerializer AUTHENTICATION_CONTEXT_SERIALIZER = new AuthenticationContextSerializer();

    public static BiConsumer<Logger, String> getAuthRecorder(ThreadContext threadContext, boolean isAuthentication) {

        final String xOpaqueId = threadContext.getHeader("X-Opaque-Id");
        if (xOpaqueId == null) {
            return (l, s) -> {};
        }

        if (isAuthentication) {
            RecordJFR.incAuthenticationCount(xOpaqueId);
        } else {
            RecordJFR.incAuthorizationCount(xOpaqueId);
        }

        final long startTime = System.nanoTime();

        return (logger, securityAction) -> {
            final long stopTime = System.nanoTime();
            final long duration = stopTime - startTime;
//            String username = "unknown";
//            String realm = "unknown";
//            try {
//                final Authentication authentication = AUTHENTICATION_CONTEXT_SERIALIZER.readFromContext(threadContext);
//                username = authentication.getUser().principal();
//                realm = authentication.getAuthenticationType().toString();
//            } catch (IOException e) {
//            }
//                logger.warn("{}: request [{}] [{},{}] [{}]. Took [{}]",
//                    isAuthentication ? "authentication" : "authorization",
//                    xOpaqueId, username, realm, securityAction, duration);
            if (isAuthentication) {
                RecordJFR.addAuthenticationDuration(xOpaqueId, duration);
            } else {
                RecordJFR.addAuthorizationDuration(xOpaqueId, duration);
            }
        };
    }

}
