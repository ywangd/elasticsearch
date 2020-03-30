package org.elasticsearch.xpack.core.security;

import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.TriConsumer;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.xpack.core.security.authc.Authentication;

import java.io.IOException;

public class SecurityHelper {

    public static TriConsumer<ThreadContext, Logger, String> getAuthRecorder(String category) {
        final long startTime = System.nanoTime();
        return (threadContext, logger, securityAction) -> {
            final String xOpaqueId = threadContext.getHeader("X-Opaque-Id");
            if (xOpaqueId != null) {
                final long stopTime = System.nanoTime();
                final long duration = stopTime - startTime;
                String username = "unknown";
                String realm = "unknown";
                try {
                    final Authentication authentication = Authentication.readFromContext(threadContext);
                    username = authentication.getUser().principal();
                    realm = authentication.getAuthenticationType().toString();
                } catch (IOException e) {
                }
                logger.warn("{}: request [{}] [{},{}] [{}]. Took [{}]",
                    category, xOpaqueId, username, realm, securityAction, duration);
            }
        };
    }

}
