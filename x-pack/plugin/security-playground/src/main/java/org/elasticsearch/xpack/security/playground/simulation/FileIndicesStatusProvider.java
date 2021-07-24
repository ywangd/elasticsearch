/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.playground.simulation;

import com.carrotsearch.hppc.cursors.ObjectCursor;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchParseException;
import org.elasticsearch.Version;
import org.elasticsearch.cluster.metadata.AliasMetadata;
import org.elasticsearch.cluster.metadata.DataStream;
import org.elasticsearch.cluster.metadata.DataStreamAlias;
import org.elasticsearch.cluster.metadata.IndexAbstraction;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.DeprecationHandler;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.core.CheckedRunnable;
import org.elasticsearch.env.Environment;
import org.elasticsearch.index.Index;
import org.elasticsearch.watcher.FileChangesListener;
import org.elasticsearch.watcher.FileWatcher;
import org.elasticsearch.watcher.ResourceWatcherService;
import org.elasticsearch.xpack.core.XPackPlugin;
import org.elasticsearch.xpack.core.security.xcontent.XContentUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.stream.Collectors;

import static org.elasticsearch.cluster.metadata.IndexMetadata.INDEX_HIDDEN_SETTING;
import static org.elasticsearch.cluster.metadata.IndexMetadata.INDEX_NUMBER_OF_REPLICAS_SETTING;
import static org.elasticsearch.cluster.metadata.IndexMetadata.INDEX_NUMBER_OF_SHARDS_SETTING;
import static org.elasticsearch.cluster.metadata.IndexMetadata.INDEX_ROUTING_PARTITION_SIZE_SETTING;
import static org.elasticsearch.cluster.metadata.IndexMetadata.SETTING_INDEX_UUID;
import static org.elasticsearch.cluster.metadata.IndexMetadata.SETTING_INDEX_VERSION_CREATED;
import static org.elasticsearch.common.xcontent.XContentParser.Token;
import static org.elasticsearch.common.xcontent.XContentParserUtils.ensureExpectedToken;

public class FileIndicesStatusProvider implements IndicesStatusProvider {

    private static final Logger logger = LogManager.getLogger(FileIndicesStatusProvider.class);

    private final Path file;
    private volatile IndicesStatus indicesStatus;

    public FileIndicesStatusProvider(Environment env, ResourceWatcherService resourceWatcherService) {
        this.file = XPackPlugin.resolveConfigFile(env, "index_abstractions.json");
        final SortedMap<String, IndexAbstraction> indexAbstractionLookup = parseFile(file);
        if (indexAbstractionLookup != null) {
            this.indicesStatus = new IndicesStatus(indexAbstractionLookup);
        } else {
            this.indicesStatus = null;
        }
        FileWatcher watcher = new FileWatcher(file.getParent());
        watcher.addListener(new FileChangesListener() {
            @Override
            public void onFileCreated(Path file) {
                onFileChanged(file);
            }

            @Override
            public void onFileDeleted(Path file) {
                onFileChanged(file);
            }

            @Override
            public void onFileChanged(Path file) {
                if (file.equals(FileIndicesStatusProvider.this.file)) {
                    logger.info("updating index abstractions");
                    final SortedMap<String, IndexAbstraction> indexAbstractionLookup = parseFile(file);
                    if (indexAbstractionLookup != null) {
                        FileIndicesStatusProvider.this.indicesStatus = new IndicesStatus(indexAbstractionLookup);
                    } else {
                        FileIndicesStatusProvider.this.indicesStatus = null;
                    }
                }
            }
        });
        try {
            resourceWatcherService.add(watcher, ResourceWatcherService.Frequency.HIGH);
        } catch (IOException e) {
            throw new ElasticsearchException("failed to start watching index abstraction file: [{}]", file.toAbsolutePath(), e);
        }
    }

    @Override
    public IndicesStatus get() {
        return indicesStatus;
    }

    public static SortedMap<String, IndexAbstraction> parseFile(Path file) {
        if (false == Files.exists(file)) {
            return null;
        }
        logger.info("building index abstractions from file [{}]", file);
        try (InputStream in = Files.newInputStream(file, StandardOpenOption.READ)) {
            try (XContentParser parser = jsonParser(in)) {
                final MetadataRecord metadataRecord = parseMetadata(parser);
                return buildIndexAbstractions(metadataRecord);
            }
        } catch (IOException e) {
            throw new ElasticsearchParseException("Error parsing index abstractions file [{}]", e, file.toAbsolutePath());
        }
    }

    private static MetadataRecord parseMetadata(XContentParser parser) throws IOException {
        Token token = parser.nextToken();
        ensureExpectedToken(Token.START_OBJECT, token, parser);
        MetadataRecord metadataRecord = null;
        while ((token = parser.nextToken()) != Token.END_OBJECT && metadataRecord == null) {
            ensureExpectedToken(Token.FIELD_NAME, token, parser);
            if ("metadata".equals(parser.currentName())) {
                metadataRecord = doParseMetadata(parser);
            } else {
                skip(parser);
            }
        }
        if (metadataRecord == null) {
            throw new IllegalArgumentException("metadata not found in the index_abstractions.json file");
        }
        logger.info(
            "metadata section parsed: [{}] indices, [{}] data streams, [{}] data stream aliases",
            metadataRecord.indices.size(),
            metadataRecord.dataStreams.size(),
            metadataRecord.dataStreamAliases.size()
        );
        return metadataRecord;
    }

    private static SortedMap<String, IndexAbstraction> buildIndexAbstractions(MetadataRecord metadataRecord) {
        final SortedMap<String, IndexAbstraction> indexAbstractionLookup = new TreeMap<>();
        final Map<AliasMetadata, Set<IndexMetadata>> indexAliases = new HashMap<>();

        for (DataStreamRecord dataStreamRecord : metadataRecord.dataStreams.values()) {
            final List<Index> indices = new ArrayList<>();
            final List<IndexMetadata> indexMetadatas = new ArrayList<>();
            for (String indexName : dataStreamRecord.indexNames) {
                final IndexRecord indexRecord = metadataRecord.indices.get(indexName);
                if (indexRecord == null) {
                    throw new IllegalArgumentException(
                        "DataStream ["
                            + dataStreamRecord.name
                            + "] declares ["
                            + indexName
                            + "] as part of its backing indices. But the index is not found"
                    );
                }
                final Index index = new Index(indexName, indexName);
                indices.add(index);
                final IndexMetadata indexMetadata = buildIndexMetadata(indexRecord);
                indexMetadatas.add(indexMetadata);
                collectIndexAliases(indexAliases, indexMetadata);
            }

            final IndexAbstraction.DataStream dataStream = new IndexAbstraction.DataStream(
                new DataStream(
                    dataStreamRecord.name,
                    null,
                    List.copyOf(indices),
                    indices.size(),
                    Map.of(),
                    dataStreamRecord.name.startsWith("."),
                    false,
                    dataStreamRecord.system
                ),
                List.copyOf(indexMetadatas)
            );
            // data stream
            indexAbstractionLookup.put(dataStreamRecord.name, dataStream);

            // data stream backing indices
            indexMetadatas.forEach(
                indexMetadata -> {
                    indexAbstractionLookup.put(indexMetadata.getIndex().getName(), new IndexAbstraction.Index(indexMetadata, dataStream));
                }
            );
        }

        for (IndexRecord indexRecord : metadataRecord.indices.values()) {
            final IndexAbstraction index = indexAbstractionLookup.get(indexRecord.name);
            if (index == null) {
                final IndexMetadata indexMetadata = buildIndexMetadata(indexRecord);
                collectIndexAliases(indexAliases, indexMetadata);
                // regular indices
                indexAbstractionLookup.put(indexRecord.name, new IndexAbstraction.Index(indexMetadata));
            } else if (false == index instanceof IndexAbstraction.Index) {
                throw new IllegalArgumentException(
                    "expect [" + indexRecord.name + "] to be an Index, but got [" + index.getClass().getSimpleName() + "]"
                );
            }
        }

        // index aliases
        for (Map.Entry<AliasMetadata, Set<IndexMetadata>> entry : indexAliases.entrySet()) {
            final IndexAbstraction.Alias alias = new IndexAbstraction.Alias(entry.getKey(), List.copyOf(entry.getValue()));
            indexAbstractionLookup.put(alias.getName(), alias);
        }

        // data stream aliases
        for (Map.Entry<String, String[]> entry : metadataRecord.dataStreamAliases.entrySet()) {
            final IndexAbstraction existingIndexAbstraction = indexAbstractionLookup.get(entry.getKey());
            if (existingIndexAbstraction != null) {
                if (false == existingIndexAbstraction instanceof IndexAbstraction.Alias) {
                    throw new IllegalArgumentException(
                        "data stream alias name ["
                            + entry.getKey()
                            + "] already exists and it is not an Alias, but ["
                            + existingIndexAbstraction.getClass().getSimpleName()
                            + "]"
                    );
                }
                logger.info("skipping data stream alias name [{}] because it is taken by an index alias", entry.getKey());
                continue;
            }
            final List<IndexMetadata> allBackingIndexMetadatas = Arrays.stream(entry.getValue()).flatMap(dataStreamName -> {
                final IndexAbstraction dataStream = indexAbstractionLookup.get(dataStreamName);
                if (false == dataStream instanceof IndexAbstraction.DataStream) {
                    throw new IllegalArgumentException(
                        "expect [" + dataStreamName + "] to be an DataStream, but got [" + dataStream.getClass().getSimpleName() + "]"
                    );
                }
                return dataStream.getIndices().stream();
            }).collect(Collectors.toUnmodifiableList());
            final IndexAbstraction.DataStreamAlias dataStreamAlias = new IndexAbstraction.DataStreamAlias(
                new DataStreamAlias(entry.getKey(), List.of(entry.getValue()), entry.getValue()[0], null),
                allBackingIndexMetadatas,
                allBackingIndexMetadatas.get(0)
            );
            indexAbstractionLookup.put(entry.getKey(), dataStreamAlias);
        }

        logger.info("built [{}] index abstractions", indexAbstractionLookup.size());
        return indexAbstractionLookup;
    }

    private static void collectIndexAliases(Map<AliasMetadata, Set<IndexMetadata>> indexAliases, IndexMetadata indexMetadata) {
        for (ObjectCursor<String> cursor : indexMetadata.getAliases().keys()) {
            final AliasMetadata aliasMetadata = AliasMetadata.builder(cursor.value).build();
            final Set<IndexMetadata> values = indexAliases.computeIfAbsent(aliasMetadata, k -> new HashSet<>());
            values.add(indexMetadata);
        }
    }

    private static IndexMetadata buildIndexMetadata(IndexRecord indexRecord) {
        final IndexMetadata.Builder indexMetadataBuilder = IndexMetadata.builder(indexRecord.name)
            .state(IndexMetadata.State.fromString(indexRecord.state))
            .system(indexRecord.system)
            .settings(
                Settings.builder()
                    .put(INDEX_HIDDEN_SETTING.getKey(), indexRecord.hidden)
                    // TODO: read from file?
                    .put(INDEX_NUMBER_OF_SHARDS_SETTING.getKey(), 1)
                    .put(INDEX_NUMBER_OF_REPLICAS_SETTING.getKey(), 0)
                    .put(INDEX_ROUTING_PARTITION_SIZE_SETTING.getKey(), 1)
                    .put(SETTING_INDEX_UUID, indexRecord.name)
                    .put(SETTING_INDEX_VERSION_CREATED.getKey(), Version.CURRENT)
                    .build()
            );
        Arrays.stream(indexRecord.aliases)
            .map(aliasName -> AliasMetadata.builder(aliasName).build())
            .forEach(indexMetadataBuilder::putAlias);
        return indexMetadataBuilder.build();
    }

    private static MetadataRecord doParseMetadata(XContentParser parser) throws IOException {
        final MetadataRecord metadataRecord = new MetadataRecord();
        parseInObject(parser, () -> {
            if ("indices".equals(parser.currentName())) {
                metadataRecord.indices = parseIndices(parser);
            } else if ("data_stream".equals(parser.currentName())) {
                parseDataStreamOuter(parser, metadataRecord);
            } else {
                skip(parser);
            }
        });
        return metadataRecord;
    }

    private static Map<String, IndexRecord> parseIndices(XContentParser parser) throws IOException {
        final Map<String, IndexRecord> indices = new HashMap<>();
        parseInObject(parser, () -> {
            final IndexRecord indexRecord = parseIndex(parser);
            indices.put(indexRecord.name, indexRecord);
        });
        return indices;
    }

    private static IndexRecord parseIndex(XContentParser parser) throws IOException {
        final IndexRecord indexRecord = new IndexRecord(parser.currentName());
        parseInObject(parser, () -> {
            if ("state".equals(parser.currentName())) {
                ensureExpectedToken(Token.VALUE_STRING, parser.nextToken(), parser);
                indexRecord.state = parser.text();
            } else if ("system".equals(parser.currentName())) {
                indexRecord.system = readBoolean(parser);
            } else if ("aliases".equals(parser.currentName())) {
                indexRecord.aliases = readStringArray(parser);
            } else if ("settings".equals(parser.currentName())) {
                parseInObject(parser, () -> {
                    if ("hidden".equals(parser.currentName())) {
                        indexRecord.hidden = readBoolean(parser);
                    } else {
                        skip(parser);
                    }
                });
            } else {
                skip(parser);
            }
        });
        return indexRecord;
    }

    private static void parseDataStreamOuter(XContentParser parser, MetadataRecord metadataRecord) throws IOException {
        parseInObject(parser, () -> {
            if ("data_stream".equals(parser.currentName())) {
                metadataRecord.dataStreams = parseDataStreams(parser);
            } else if ("data_stream_aliases".equals(parser.currentName())) {
                metadataRecord.dataStreamAliases = parseDataStreamAliases(parser);
            }
        });
    }

    private static Map<String, String[]> parseDataStreamAliases(XContentParser parser) throws IOException {
        final Map<String, String[]> aliases = new HashMap<>();
        parseInObject(parser, () -> {
            final String aliasName = parser.currentName();
            parseInObject(parser, () -> {
                if ("data_streams".equals(parser.currentName())) {
                    aliases.put(aliasName, readStringArray(parser));
                } else {
                    skip(parser);
                }
            });
        });
        return aliases;
    }

    private static Map<String, DataStreamRecord> parseDataStreams(XContentParser parser) throws IOException {
        final Map<String, DataStreamRecord> dataStreams = new HashMap<>();
        parseInObject(parser, () -> {
            final DataStreamRecord dataStreamRecord = parseDataStream(parser);
            dataStreams.put(dataStreamRecord.name, dataStreamRecord);

        });
        return dataStreams;
    }

    private static DataStreamRecord parseDataStream(XContentParser parser) throws IOException {
        final DataStreamRecord dataStreamRecord = new DataStreamRecord(parser.currentName());
        parseInObject(parser, () -> {
            if ("hidden".equals(parser.currentName())) {
                dataStreamRecord.hidden = readBoolean(parser);
            } else if ("system".equals(parser.currentName())) {
                dataStreamRecord.system = readBoolean(parser);
            } else if ("indices".equals(parser.currentName())) {
                ensureExpectedToken(Token.START_ARRAY, parser.nextToken(), parser);
                final ArrayList<String> indexNames = new ArrayList<>();
                while (parser.nextToken() != Token.END_ARRAY) {
                    parseInCurrentObject(parser, () -> {
                        if ("index_name".equals(parser.currentName())) {
                            ensureExpectedToken(Token.VALUE_STRING, parser.nextToken(), parser);
                            indexNames.add(parser.text());
                        } else {
                            skip(parser);
                        }
                    });
                }
                dataStreamRecord.indexNames = indexNames.toArray(String[]::new);
            } else {
                skip(parser);
            }
        });
        return dataStreamRecord;
    }

    private static XContentParser jsonParser(InputStream in) throws IOException {
        return XContentType.JSON.xContent().createParser(NamedXContentRegistry.EMPTY, DeprecationHandler.THROW_UNSUPPORTED_OPERATION, in);
    }

    private static void skip(XContentParser parser) throws IOException {
        final XContentParser.Token token = parser.nextToken();
        if (token == Token.START_OBJECT || token == Token.START_ARRAY) {
            parser.skipChildren();
        }
    }

    private static boolean readBoolean(XContentParser parser) throws IOException {
        parser.nextToken();
        if (Token.VALUE_BOOLEAN == parser.currentToken()) {
            return parser.booleanValue();
        } else {
            ensureExpectedToken(Token.VALUE_STRING, parser.currentToken(), parser);
            return Boolean.parseBoolean(parser.text());
        }
    }

    private static String[] readStringArray(XContentParser parser) throws IOException {
        ensureExpectedToken(Token.START_ARRAY, parser.nextToken(), parser);
        return XContentUtils.readStringArray(parser, false);
    }

    private static void parseInObject(XContentParser parser, CheckedRunnable<IOException> runnable) throws IOException {
        // advance to read the start of the object
        XContentParser.Token token = parser.nextToken();
        ensureExpectedToken(Token.START_OBJECT, token, parser);
        while ((token = parser.nextToken()) != Token.END_OBJECT) {
            ensureExpectedToken(Token.FIELD_NAME, token, parser);
            runnable.run();
        }
    }

    private static void parseInCurrentObject(XContentParser parser, CheckedRunnable<IOException> runnable) throws IOException {
        // Do not advance the token, the current one is the start of object
        XContentParser.Token token = parser.currentToken();
        ensureExpectedToken(Token.START_OBJECT, token, parser);
        while ((token = parser.nextToken()) != Token.END_OBJECT) {
            ensureExpectedToken(Token.FIELD_NAME, token, parser);
            runnable.run();
        }
    }

    static class IndexRecord {
        String name;
        String state;
        boolean hidden;
        boolean system;
        String[] aliases = Strings.EMPTY_ARRAY;

        IndexRecord(String name) {
            this.name = name;
        }
    }

    static class DataStreamRecord {
        String name;
        String[] indexNames = Strings.EMPTY_ARRAY;
        boolean hidden;
        boolean system;

        DataStreamRecord(String name) {
            this.name = name;
        }
    }

    static class MetadataRecord {
        Map<String, IndexRecord> indices;
        Map<String, DataStreamRecord> dataStreams;
        Map<String, String[]> dataStreamAliases;
    }
}
