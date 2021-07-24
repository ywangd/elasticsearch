/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground.simulation;

import org.elasticsearch.cluster.metadata.IndexAbstraction;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.common.collect.ImmutableOpenMap;

import java.util.ArrayList;
import java.util.List;
import java.util.SortedMap;
import java.util.function.Supplier;

public interface IndicesStatusProvider extends Supplier<IndicesStatusProvider.IndicesStatus> {

    class IndicesStatus {
        public final SortedMap<String, IndexAbstraction> indexAbstractionLookup;
        public final ImmutableOpenMap<String, IndexMetadata> indexLookup;
        public final String[] allIndices;
        public final String[] visibleIndices;
        public final String[] allOpenIndices;
        public final String[] visibleOpenIndices;
        public final String[] allClosedIndices;
        public final String[] visibleClosedIndices;

        public IndicesStatus(SortedMap<String, IndexAbstraction> indexAbstractionLookup) {
            this.indexAbstractionLookup = indexAbstractionLookup;
            final List<String> allIndices = new ArrayList<>();
            final List<String> visibleIndices = new ArrayList<>();
            final List<String> allOpenIndices = new ArrayList<>();
            final List<String> visibleOpenIndices = new ArrayList<>();
            final List<String> allClosedIndices = new ArrayList<>();
            final List<String> visibleClosedIndices = new ArrayList<>();
            final ImmutableOpenMap.Builder<String, IndexMetadata> indexLookupBuilder = new ImmutableOpenMap.Builder<>();
            indexAbstractionLookup.values()
                .stream()
                .filter(indexAbstraction -> indexAbstraction.getType() == IndexAbstraction.Type.CONCRETE_INDEX)
                .map(indexAbstraction -> indexAbstraction.getIndices().get(0))
                .forEach(indexMetadata -> {
                    final String indexName = indexMetadata.getIndex().getName();
                    indexLookupBuilder.put(indexName, indexMetadata);
                    allIndices.add(indexName);
                    final boolean visible = false == IndexMetadata.INDEX_HIDDEN_SETTING.get(indexMetadata.getSettings());

                    if (visible) {
                        visibleIndices.add(indexName);

                    }

                    if (indexMetadata.getState() == IndexMetadata.State.OPEN) {
                        allOpenIndices.add(indexName);
                        if (visible) {
                            visibleOpenIndices.add(indexName);
                        }
                    } else if (indexMetadata.getState() == IndexMetadata.State.CLOSE) {
                        allClosedIndices.add(indexName);
                        if (visible) {
                            visibleClosedIndices.add(indexName);
                        }
                    }
                });
            this.indexLookup = indexLookupBuilder.build();
            this.allIndices = allIndices.toArray(String[]::new);
            this.visibleIndices = visibleIndices.toArray(String[]::new);
            this.allOpenIndices = allOpenIndices.toArray(String[]::new);
            this.visibleOpenIndices = visibleOpenIndices.toArray(String[]::new);
            this.allClosedIndices = allClosedIndices.toArray(String[]::new);
            this.visibleClosedIndices = visibleClosedIndices.toArray(String[]::new);
        }
    }
}
