/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground.simulation;

import org.elasticsearch.cluster.metadata.IndexAbstraction;
import org.elasticsearch.test.ESTestCase;

import java.nio.file.Path;
import java.util.Map;

public class FileIndicesStatusProviderTests extends ESTestCase {

    public void testParseFile() {
        final Path file = getDataPath("index_abstractions.json");
        final Map<String, IndexAbstraction> indexAbstractions = FileIndicesStatusProvider.parseFile(file);
        assertIndexAbstractions(indexAbstractions);
    }

    public void testParseClusterState() {
        final Path file = getDataPath("cluster_state.json");
        final Map<String, IndexAbstraction> indexAbstractions = FileIndicesStatusProvider.parseFile(file);
        assertIndexAbstractions(indexAbstractions);
    }

    private void assertIndexAbstractions(Map<String, IndexAbstraction> indexAbstractions) {

        // assertThat(indexAbstractions.size(), equalTo(10));
        //
        // final IndexAbstraction.Index index = (IndexAbstraction.Index) indexAbstractions.get("index");
        // assertThat(index.getParentDataStream(), nullValue());
        // final IndexMetadata indexMetadata = index.getIndices().get(0);
        // assertThat(indexMetadata.isSystem(), is(false));
        // assertThat(indexMetadata.getState(), is(IndexMetadata.State.OPEN));
        // assertThat(indexMetadata.getSettings().getAsBoolean("hidden", false), is(false));
        // final ImmutableOpenMap<String, AliasMetadata> indexAliases = indexMetadata.getAliases();
        // assertThat(indexAliases.size(), equalTo(2));
        // assertThat(indexAliases.containsKey("alias_indices"), is(true));
        // assertThat(indexAliases.containsKey("my-write-alias"), is(true));
        //
        // final IndexAbstraction.Index backingIndex = (IndexAbstraction.Index)
        // indexAbstractions.get(".ds-my-data-stream-2021.08.01-000001");
        // final IndexMetadata backingIndexMetadata = backingIndex.getIndices().get(0);
        // assertThat(backingIndexMetadata.getState(), is(IndexMetadata.State.OPEN));
        // assertThat(backingIndexMetadata.getSettings().getAsBoolean("hidden", false), is(false));
        // assertThat(backingIndexMetadata.getAliases().size(), equalTo(0));
        //
        // final IndexAbstraction.DataStream dataStreamAbstraction = (IndexAbstraction.DataStream) indexAbstractions.get("my-data-stream");
        // assertThat(backingIndex.getParentDataStream(), is(dataStreamAbstraction));
        // assertThat(dataStreamAbstraction.getParentDataStream(), nullValue());
        // assertThat(dataStreamAbstraction.getIndices().size(), equalTo(1));
        // assertThat(dataStreamAbstraction.getIndices().get(0), is(backingIndexMetadata));
        // final DataStream dataStream = dataStreamAbstraction.getDataStream();
        // assertThat(dataStream.isHidden(), is(false));
        // assertThat(dataStream.isSystem(), is(false));
        // assertThat(
        // dataStream.getIndices().stream().map(Index::getName).collect(Collectors.toUnmodifiableSet()),
        // equalTo(Set.of(".ds-my-data-stream-2021.08.01-000001"))
        // );
        // assertThat(dataStream.getGeneration(), equalTo(1L));
        //
        // final IndexAbstraction.Alias indexAlias = (IndexAbstraction.Alias) indexAbstractions.get("alias_indices");
        // assertThat(indexAlias.getIndices().size(), equalTo(1));
        // assertThat(indexAlias.getIndices().get(0), is(indexMetadata));
        //
        // final IndexAbstraction.Alias dataStreamAliasAbstraction = (IndexAbstraction.Alias) indexAbstractions.get("alias_data_streams");
        // assertThat(dataStreamAliasAbstraction.getIndices().size(), equalTo(1));
        // assertThat(dataStreamAliasAbstraction.getIndices().get(0), is(backingIndexMetadata));
        // assertThat(dataStreamAliasAbstraction.isDataStreamRelated(), is(true));
        // assertThat(dataStreamAliasAbstraction.getIndices(), equalTo(List.of(backingIndexMetadata)));
        //
        // assertThat(indexAbstractions.get("my-write-alias").getClass(), is(IndexAbstraction.Alias.class));
        // assertThat(indexAbstractions.get("my-data-stream").getClass(), is(IndexAbstraction.DataStream.class));
    }
}
