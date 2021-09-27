/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground.authz;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.cluster.metadata.IndexAbstraction;
import org.elasticsearch.cluster.metadata.Metadata;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.node.Node;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.xpack.core.security.SecurityContext;
import org.elasticsearch.xpack.core.security.action.user.GetUserPrivilegesRequest;
import org.elasticsearch.xpack.core.security.action.user.GetUserPrivilegesResponse;
import org.elasticsearch.xpack.core.security.action.user.HasPrivilegesRequest;
import org.elasticsearch.xpack.core.security.action.user.HasPrivilegesResponse;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authz.AuthorizationEngine;
import org.elasticsearch.xpack.core.security.authz.ResolvedIndices;
import org.elasticsearch.xpack.core.security.authz.permission.Role;
import org.elasticsearch.xpack.core.security.authz.privilege.ApplicationPrivilegeDescriptor;
import org.elasticsearch.xpack.security.authz.AuthorizationService;
import org.elasticsearch.xpack.security.authz.RBACEngine;
import org.elasticsearch.xpack.security.playground.SecurityPlaygroundPlugin;
import org.elasticsearch.xpack.security.playground.actions.SPIndexAction;
import org.elasticsearch.xpack.security.playground.actions.TransportSPClusterAction;
import org.elasticsearch.xpack.security.playground.metric.AuthorizationMetrics;
import org.elasticsearch.xpack.security.playground.metric.InstrumentedMethod;
import org.elasticsearch.xpack.security.playground.simulation.IndicesStatusProvider;
import org.elasticsearch.xpack.security.playground.support.TextLikeStreamOutput;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;

import static org.elasticsearch.xpack.core.security.authz.AuthorizationServiceField.ORIGINATING_ACTION_KEY;

public class InstrumentedAuthorizationEngine implements AuthorizationEngine {

    private static final String X_SECURITY_AUTHORIZATION_COUNTER = "x-security-authorization-counter";
    private static final Logger logger = LogManager.getLogger(InstrumentedAuthorizationEngine.class);

    private static final Consumer<AuthorizationInfo> EMPTY_CONSUMER = authorizationInfo -> {};
    private static final Runnable EMPTY_RUNNABLE = () -> {};

    private final Settings settings;
    private final ThreadContext threadContext;
    private final SecurityContext securityContext;
    private final String nodeName;
    private final AtomicReference<RBACEngine> rbacEngineRef = new AtomicReference<>();

    private final boolean instrumentedRoleEnabled;
    private final boolean instrumentedRelevantInternalActionEnabled;
    private final boolean instrumentedIndicesAndAliasesResolverEnabled;
    // bridge method for creating an instrumentedRole
    private final Method bridgeMethod;

    public InstrumentedAuthorizationEngine(Settings settings, ThreadContext threadContext) {
        this.settings = settings;
        this.threadContext = threadContext;
        this.securityContext = new SecurityContext(settings, threadContext);
        this.nodeName = Node.NODE_NAME_SETTING.get(settings);
        this.instrumentedRoleEnabled = SecurityPlaygroundPlugin.INSTRUMENTED_ROLE_ENABLED.get(settings);
        this.instrumentedRelevantInternalActionEnabled = SecurityPlaygroundPlugin.INSTRUMENTED_RELEVANT_INTERNAL_ACTIONS_ENABLED.get(
            settings
        );
        this.instrumentedIndicesAndAliasesResolverEnabled = SecurityPlaygroundPlugin.INSTRUMENTED_INDICES_AND_ALIASES_RESOLVER_ENABLED.get(
            settings
        );
        maybeInjectClasspath();
        bridgeMethod = maybeInstrumentRole();
    }

    @Override
    public void resolveAuthorizationInfo(RequestInfo requestInfo, ActionListener<AuthorizationInfo> listener) {
        // TODO: Any other better way for tracking this? Alternatives: threadLocal, server interceptor for flagging threadContext
        // Differentiate the different number of times that the authorization engine is invoked at different layer
        final int authorizationIndex = getAndIncrementAuthorizationIndex();
        final Consumer<AuthorizationInfo> stopMetric = maybeStartMetric(InstrumentedMethod.RESOLVE_AUTHORIZATION_INFO, requestInfo);
        getRbacEngine().resolveAuthorizationInfo(requestInfo, ActionListener.wrap(authorizationInfo -> {
            final AuthorizationInfo finalAuthorizationInfo = maybeInstrumentAuthorizationInfo(
                authorizationInfo,
                requestInfo,
                authorizationIndex
            );
            stopMetric.accept(finalAuthorizationInfo);
            listener.onResponse(finalAuthorizationInfo);
        }, listener::onFailure));
    }

    @Override
    public void authorizeRunAs(RequestInfo requestInfo, AuthorizationInfo authorizationInfo, ActionListener<AuthorizationResult> listener) {
        final Consumer<AuthorizationInfo> stopMetric = maybeStartMetric(InstrumentedMethod.AUTHORIZE_RUN_AS, requestInfo);
        getRbacEngine().authorizeRunAs(requestInfo, authorizationInfo, ActionListener.wrap(authorizationResult -> {
            stopMetric.accept(authorizationInfo);
            listener.onResponse(authorizationResult);
        }, listener::onFailure));
    }

    @Override
    public void authorizeClusterAction(
        RequestInfo requestInfo,
        AuthorizationInfo authorizationInfo,
        ActionListener<AuthorizationResult> listener
    ) {
        final Consumer<AuthorizationInfo> stopMetric = maybeStartMetric(InstrumentedMethod.AUTHORIZE_CLUSTER_ACTION, requestInfo);
        getRbacEngine().authorizeClusterAction(requestInfo, authorizationInfo, ActionListener.wrap(authorizationResult -> {
            stopMetric.accept(authorizationInfo);
            listener.onResponse(authorizationResult);
        }, listener::onFailure));
    }

    @Override
    public void authorizeIndexAction(
        RequestInfo requestInfo,
        AuthorizationInfo authorizationInfo,
        AsyncSupplier<ResolvedIndices> indicesAsyncSupplier,
        Map<String, IndexAbstraction> aliasOrIndexLookup,
        ActionListener<IndexAuthorizationResult> listener
    ) {
        final Map<String, IndexAbstraction> finalAliasOrIndexLookup = maybeSimulateIndexAbstractions(
            requestInfo.getAction(),
            aliasOrIndexLookup
        );
        final Consumer<AuthorizationInfo> stopMetric = maybeStartMetric(InstrumentedMethod.AUTHORIZE_INDEX_ACTION, requestInfo);
        getRbacEngine().authorizeIndexAction(
            requestInfo,
            authorizationInfo,
            indicesAsyncSupplier,
            finalAliasOrIndexLookup,
            ActionListener.wrap(indexAuthorizationResult -> {
                stopMetric.accept(authorizationInfo);
                listener.onResponse(indexAuthorizationResult);
            }, listener::onFailure)
        );
    }

    @Override
    public void loadAuthorizedIndices(
        RequestInfo requestInfo,
        AuthorizationInfo authorizationInfo,
        Map<String, IndexAbstraction> indicesLookup,
        ActionListener<Set<String>> listener
    ) {
        final Map<String, IndexAbstraction> finalAliasOrIndexLookup = maybeSimulateIndexAbstractions(
            requestInfo.getAction(),
            indicesLookup
        );
        final Consumer<AuthorizationInfo> stopMetric = maybeStartMetric(InstrumentedMethod.LOAD_AUTHORIZED_INDICES, requestInfo);
        getRbacEngine().loadAuthorizedIndices(requestInfo, authorizationInfo, finalAliasOrIndexLookup, ActionListener.wrap(names -> {
            logger.trace(
                () -> new ParameterizedMessage("[{}] resolved [{}] names", InstrumentedMethod.LOAD_AUTHORIZED_INDICES, names.size())
            );
            stopMetric.accept(authorizationInfo);
            listener.onResponse(names);
        }, listener::onFailure));
    }

    @Override
    public void validateIndexPermissionsAreSubset(
        RequestInfo requestInfo,
        AuthorizationInfo authorizationInfo,
        Map<String, List<String>> indexNameToNewNames,
        ActionListener<AuthorizationResult> listener
    ) {
        getRbacEngine().validateIndexPermissionsAreSubset(requestInfo, authorizationInfo, indexNameToNewNames, listener);
    }

    @Override
    public void checkPrivileges(
        Authentication authentication,
        AuthorizationInfo authorizationInfo,
        HasPrivilegesRequest hasPrivilegesRequest,
        Collection<ApplicationPrivilegeDescriptor> applicationPrivilegeDescriptors,
        ActionListener<HasPrivilegesResponse> listener
    ) {
        getRbacEngine().checkPrivileges(authentication, authorizationInfo, hasPrivilegesRequest, applicationPrivilegeDescriptors, listener);
    }

    @Override
    public void getUserPrivileges(
        Authentication authentication,
        AuthorizationInfo authorizationInfo,
        GetUserPrivilegesRequest request,
        ActionListener<GetUserPrivilegesResponse> listener
    ) {
        getRbacEngine().getUserPrivileges(authentication, authorizationInfo, request, listener);
    }

    private RBACEngine getRbacEngine() {
        if (rbacEngineRef.get() == null) {
            maybeInstrumentRelevantInternalAction();
            maybeInstrumentIndicesAndAliasesResolver();
            logger.info("Instantiate RBACEngine with injected [{}]", TransportSPClusterAction.compositeRolesStore);
            rbacEngineRef.compareAndSet(null, new RBACEngine(settings, TransportSPClusterAction.compositeRolesStore));
        }
        return rbacEngineRef.get();
    }

    private String getXOpaqueId() {
        return threadContext.getHeader(Task.X_OPAQUE_ID);
    }

    private String getOriginatingAction() {
        return threadContext.getTransient(ORIGINATING_ACTION_KEY);
    }

    private boolean isInstantaneousMetric() {
        return threadContext.getHeader(Task.TRACE_ID) != null;
    }

    private int getAuthorizationIndex() {
        final List<String> authorizationCounter = threadContext.getResponseHeaders().get(X_SECURITY_AUTHORIZATION_COUNTER);
        return authorizationCounter == null ? 0 : authorizationCounter.size() - 1;
    }

    private int getAndIncrementAuthorizationIndex() {
        final int authorizationIndex;
        if (isInstantaneousMetric()) {
            final List<String> authorizationCounter = threadContext.getResponseHeaders().get(X_SECURITY_AUTHORIZATION_COUNTER);
            if (authorizationCounter == null) {
                authorizationIndex = 0;
                threadContext.addResponseHeader(X_SECURITY_AUTHORIZATION_COUNTER, "0");
            } else {
                authorizationIndex = authorizationCounter.size();
                threadContext.addResponseHeader(X_SECURITY_AUTHORIZATION_COUNTER, String.valueOf(authorizationCounter.size()));
            }
        } else {
            authorizationIndex = 0;
        }
        return authorizationIndex;
    }

    protected void maybeInjectClasspath() {
        if (instrumentedRoleEnabled || instrumentedIndicesAndAliasesResolverEnabled) {
            logger.info("Injecting classpath");
            AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
                try {
                    final Method addURLMethod = URLClassLoader.class.getDeclaredMethod("addURL", URL.class);
                    addURLMethod.setAccessible(true);
                    final URLClassLoader thisClassloader = (URLClassLoader) InstrumentedAuthorizationEngine.class.getClassLoader();
                    final Path basePath = Paths.get(thisClassloader.getURLs()[0].getFile()).getParent();

                    final ClassLoader roleClassLoader = Role.class.getClassLoader();
                    addURLMethod.invoke(roleClassLoader, basePath.resolve("core").toFile().toURI().toURL());
                    final ClassLoader rbacEngineClassLoader = RBACEngine.class.getClassLoader();
                    addURLMethod.invoke(rbacEngineClassLoader, basePath.resolve("security").toFile().toURI().toURL());
                    return null;
                } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException | MalformedURLException e) {
                    throw new ElasticsearchException(e);
                }
            });
        }
    }

    private Consumer<AuthorizationInfo> maybeStartMetric(InstrumentedMethod method, RequestInfo requestInfo) {
        final String xOpaqueId = getXOpaqueId();
        if (xOpaqueId == null) {
            return EMPTY_CONSUMER;
        }

        if (isInstantaneousMetric()) {
            final String action = requestInfo.getAction();
            final String originatingAction = getOriginatingAction();
            final int requestHash = System.identityHashCode(requestInfo.getRequest());
            final int authorizationIndex = threadContext.getResponseHeaders().get(X_SECURITY_AUTHORIZATION_COUNTER).size() - 1;
            final String username = securityContext.getAuthentication().getUser().principal();
            logger.trace(() -> {
                if (method == InstrumentedMethod.RESOLVE_AUTHORIZATION_INFO) {
                    try (TextLikeStreamOutput out = new TextLikeStreamOutput()) {
                        try {
                            requestInfo.getRequest().writeTo(out);
                        } catch (IOException e) {
                            throw new ElasticsearchException(e);
                        }
                        return new ParameterizedMessage(
                            "[{}] ----->>> action [{}], originatingAction [{}], request [{}@{}], "
                                + "xOpaqueId [{}], user [{}], request-class [{}], body [{}]",
                            method,
                            action,
                            originatingAction,
                            requestHash,
                            authorizationIndex,
                            xOpaqueId,
                            username,
                            requestInfo.getRequest().getClass().getSimpleName(),
                            out
                        );
                    }
                } else {
                    return new ParameterizedMessage(
                        "[{}] ----->>> action [{}], originatingAction [{}], request [{}@{}], xOpaqueId [{}], user [{}]",
                        method,
                        action,
                        originatingAction,
                        requestHash,
                        authorizationIndex,
                        xOpaqueId,
                        username
                    );
                }
            });

            final long startTime = System.nanoTime();
            return authorizationInfo -> {
                final long elapsed = System.nanoTime() - startTime;
                AuthorizationMetrics.addInstantMetric(
                    nodeName,
                    username,
                    xOpaqueId,
                    method,
                    action,
                    originatingAction,
                    requestHash,
                    authorizationIndex,
                    startTime,
                    elapsed
                );
                logger.trace(
                    () -> new ParameterizedMessage(
                        "[{}] <<<----- action [{}], request [{}@{}], xOpaqueId [{}], role [{}], took: [{}ns]",
                        method,
                        action,
                        requestHash,
                        authorizationIndex,
                        xOpaqueId,
                        authorizationInfo.asMap(),
                        String.format(Locale.ROOT, "%,d", elapsed)
                    )
                );
            };
        } else {
            logger.trace(() -> new ParameterizedMessage("Histogram recording for method [{}], xOpaqueId [{}]", method, xOpaqueId));
            final long startTime = System.nanoTime();
            return authorizationInfo -> {
                final long elapsed = System.nanoTime() - startTime;
                AuthorizationMetrics.addHistogramMetric(xOpaqueId, method, elapsed);
            };
        }
    }

    private Method maybeInstrumentRole() {
        if (this.instrumentedRoleEnabled) {
            logger.info("Instrumented Role enabled");
            return AccessController.doPrivileged((PrivilegedAction<Method>) () -> {
                try {
                    final ClassLoader roleClassLoader = Role.class.getClassLoader();
                    Class.forName("org.elasticsearch.xpack.core.security.authz.permission.InstrumentedRole", true, roleClassLoader);

                    final ClassLoader rbacEngineClassLoader = RBACEngine.class.getClassLoader();
                    final Class<?> bridgeClass = Class.forName(
                        "org.elasticsearch.xpack.security.authz.RBACEngineAuthorizationInfoBridge",
                        true,
                        rbacEngineClassLoader
                    );
                    return bridgeClass.getDeclaredMethods()[0];
                } catch (ClassNotFoundException e) {
                    throw new ElasticsearchException(e);
                }
            });
        } else {
            return null;
        }
    }

    private AuthorizationInfo maybeInstrumentAuthorizationInfo(
        AuthorizationInfo authorizationInfo,
        RequestInfo requestInfo,
        int authorizationIndex
    ) {
        final String xOpaqueId = getXOpaqueId();
        if (false == instrumentedRoleEnabled || xOpaqueId == null) {
            return authorizationInfo;
        }
        final String action = requestInfo.getAction();
        final int requestHash = System.identityHashCode(requestInfo.getRequest());
        final boolean isInstantaneousMetric = isInstantaneousMetric();

        final Function<String, Runnable> startMetricFunc = methodName -> {
            final InstrumentedMethod method = InstrumentedMethod.valueOf(methodName);
            logger.trace(
                new ParameterizedMessage(
                    "[{}] ----->>> action [{}], request [{}@{}], xOpaqueId [{}]",
                    method,
                    action,
                    requestHash,
                    authorizationIndex,
                    xOpaqueId
                )
            );
            final long startTime = System.nanoTime();
            return () -> {
                final long elapsed = System.nanoTime() - startTime;
                if (isInstantaneousMetric) {
                    AuthorizationMetrics.addInstantMetric(xOpaqueId, method, action, requestHash, authorizationIndex, startTime, elapsed);
                    logger.trace(
                        new ParameterizedMessage(
                            "[{}] <<<----- action [{}], request [{}@{}], xOpaqueId [{}], took: [{}ns]",
                            method,
                            action,
                            requestHash,
                            authorizationIndex,
                            xOpaqueId,
                            String.format(Locale.ROOT, "%,d", elapsed)
                        )
                    );
                } else {
                    AuthorizationMetrics.addHistogramMetric(xOpaqueId, method, elapsed);
                }
            };
        };

        try {
            return (AuthorizationInfo) bridgeMethod.invoke(null, authorizationInfo, startMetricFunc);
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new ElasticsearchException(e);
        }
    }

    private void maybeInstrumentRelevantInternalAction() {
        if (instrumentedRelevantInternalActionEnabled) {
            logger.info("Instrumented Relevant Internal Action enabled");
            AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
                try {
                    final Field rbacEngineField = AuthorizationService.class.getDeclaredField("rbacEngine");
                    rbacEngineField.setAccessible(true);
                    rbacEngineField.set(TransportSPClusterAction.authorizationService, this);
                    return null;
                } catch (NoSuchFieldException | IllegalAccessException e) {
                    throw new ElasticsearchException(e);
                }
            });
        }
    }

    private void maybeInstrumentIndicesAndAliasesResolver() {
        if (instrumentedIndicesAndAliasesResolverEnabled) {
            logger.info("Instrumented IndicesAndAliasesResolver enabled");
            final BiFunction<String, Integer, Runnable> startMetricFunc = (action, requestHash) -> {
                final String xOpaqueId = getXOpaqueId();
                if (xOpaqueId == null) {
                    return EMPTY_RUNNABLE;
                }
                final int authorizationIndex = getAuthorizationIndex();
                logger.trace(
                    new ParameterizedMessage(
                        "[{}] ----->>> action [{}], request [{}@{}], xOpaqueId [{}]",
                        "iaar_resolve",
                        action,
                        requestHash,
                        authorizationIndex,
                        xOpaqueId
                    )
                );
                final long startTime = System.nanoTime();
                return () -> {
                    final long elapsed = System.nanoTime() - startTime;
                    if (isInstantaneousMetric()) {
                        AuthorizationMetrics.addInstantMetric(
                            xOpaqueId,
                            InstrumentedMethod.IAAR_RESOLVE,
                            action,
                            requestHash,
                            authorizationIndex,
                            startTime,
                            elapsed
                        );
                        logger.trace(
                            new ParameterizedMessage(
                                "[{}] <<<----- action [{}], request [{}@{}], xOpaqueId [{}], took: [{}ns]",
                                "iaar_resolve",
                                action,
                                requestHash,
                                authorizationIndex,
                                xOpaqueId,
                                String.format(Locale.ROOT, "%,d", elapsed)
                            )
                        );
                    } else {
                        AuthorizationMetrics.addHistogramMetric(xOpaqueId, InstrumentedMethod.IAAR_RESOLVE, elapsed);
                    }
                };
            };
            AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
                try {
                    final Constructor<?> metadataConstructor = Metadata.class.getDeclaredConstructors()[0];
                    metadataConstructor.setAccessible(true);
                    final Class<?> instrumentedClass = Class.forName(
                        "org.elasticsearch.xpack.security.authz.InstrumentedIndicesAndAliasesResolver",
                        true,
                        AuthorizationService.class.getClassLoader()
                    );
                    final Constructor<?> constructor = instrumentedClass.getDeclaredConstructors()[0];
                    final Object instrumentedResolver = constructor.newInstance(
                        settings,
                        SecurityPlaygroundPlugin.CLUSTER_SERVICE_REF.get(),
                        SecurityPlaygroundPlugin.INDEX_NAME_EXPRESSION_RESOLVER_REF.get(),
                        startMetricFunc,
                        (BiFunction<String, Metadata, Metadata>) (action, metadata) -> {
                            if (SPIndexAction.NAME.equals(action)) {
                                final IndicesStatusProvider.IndicesStatus indicesStatus =
                                    TransportSPClusterAction.fileIndexAbstractionsProvider.get();
                                if (indicesStatus != null) {
                                    try {
                                        return (Metadata) metadataConstructor.newInstance(
                                            metadata.clusterUUID(),
                                            metadata.clusterUUIDCommitted(),
                                            metadata.version(),
                                            metadata.coordinationMetadata(),
                                            metadata.transientSettings(),
                                            metadata.persistentSettings(),
                                            metadata.hashesOfConsistentSettings(),
                                            indicesStatus.indexLookup,
                                            metadata.templates(),
                                            metadata.customs(),
                                            indicesStatus.allIndices,
                                            indicesStatus.visibleIndices,
                                            indicesStatus.allOpenIndices,
                                            indicesStatus.visibleOpenIndices,
                                            indicesStatus.allClosedIndices,
                                            indicesStatus.visibleClosedIndices,
                                            indicesStatus.indexAbstractionLookup
                                        );
                                    } catch (InvocationTargetException | InstantiationException | IllegalAccessException e) {
                                        throw new ElasticsearchException(e);
                                    }
                                }
                            }
                            return metadata;
                        }
                    );
                    final Field indicesAndAliasesResolverField = AuthorizationService.class.getDeclaredField("indicesAndAliasesResolver");
                    indicesAndAliasesResolverField.setAccessible(true);
                    indicesAndAliasesResolverField.set(TransportSPClusterAction.authorizationService, instrumentedResolver);
                    return null;
                } catch (NoSuchFieldException | IllegalAccessException | ClassNotFoundException | InstantiationException
                    | InvocationTargetException e) {
                    throw new ElasticsearchException(e);
                }
            });
        }
    }

    // TODO: two calls of this method may get different results
    private Map<String, IndexAbstraction> maybeSimulateIndexAbstractions(String action, Map<String, IndexAbstraction> indexAbstractions) {
        Map<String, IndexAbstraction> finalAliasOrIndexLookup = null;
        if (SPIndexAction.NAME.equals(action)) {
            final IndicesStatusProvider.IndicesStatus indicesStatus = TransportSPClusterAction.fileIndexAbstractionsProvider.get();
            if (indicesStatus != null) {
                finalAliasOrIndexLookup = indicesStatus.indexAbstractionLookup;
            }
        }

        if (finalAliasOrIndexLookup == null) {
            finalAliasOrIndexLookup = indexAbstractions;
        }

        // TODO: merge real and simulated lookups?
        return finalAliasOrIndexLookup;
    }
}
