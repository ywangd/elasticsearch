/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

package org.elasticsearch.xpack.core.security.action;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.ParseField;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;
import org.elasticsearch.common.xcontent.ConstructingObjectParser;
import org.elasticsearch.common.xcontent.ToXContentObject;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentParser;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import static org.elasticsearch.common.xcontent.ConstructingObjectParser.constructorArg;
import static org.elasticsearch.common.xcontent.ConstructingObjectParser.optionalConstructorArg;

/**
 * Response for invalidation of one or more API keys result.<br>
 * The result contains information about:
 * <ul>
 * <li>API key ids that were actually invalidated</li>
 * <li>API key ids that were not invalidated in this request because they were already invalidated</li>
 * <li>how many errors were encountered while invalidating API keys and the error details</li>
 * </ul>
 */
public final class InvalidateApiKeyTemplateResponse extends ActionResponse implements ToXContentObject, Writeable {

    private final List<String> invalidatedApiKeyTemplates;
    private final List<String> previouslyInvalidatedApiKeyTemplates;
    private final List<ElasticsearchException> errors;

    public InvalidateApiKeyTemplateResponse(StreamInput in) throws IOException {
        super(in);
        this.invalidatedApiKeyTemplates = in.readList(StreamInput::readString);
        this.previouslyInvalidatedApiKeyTemplates = in.readList(StreamInput::readString);
        this.errors = in.readList(StreamInput::readException);
    }

    /**
     * Constructor for API keys invalidation response
     * @param invalidatedApiKeyTemplates list of invalidated API key ids
     * @param previouslyInvalidatedApiKeyTemplates list of previously invalidated API key ids
     * @param errors list of encountered errors while invalidating API keys
     */
    public InvalidateApiKeyTemplateResponse(List<String> invalidatedApiKeyTemplates,
                                    List<String> previouslyInvalidatedApiKeyTemplates,
                                    @Nullable List<ElasticsearchException> errors) {
        this.invalidatedApiKeyTemplates = Objects.requireNonNull(invalidatedApiKeyTemplates, "invalidated_api_key_templates must be provided");
        this.previouslyInvalidatedApiKeyTemplates = Objects.requireNonNull(
            previouslyInvalidatedApiKeyTemplates,
                "previously_invalidated_api_key_templates must be provided");
        if (null != errors) {
            this.errors = errors;
        } else {
            this.errors = Collections.emptyList();
        }
    }

    public static InvalidateApiKeyTemplateResponse emptyResponse() {
        return new InvalidateApiKeyTemplateResponse(Collections.emptyList(), Collections.emptyList(), Collections.emptyList());
    }

    public List<String> getInvalidatedApiKeyTemplates() {
        return invalidatedApiKeyTemplates;
    }

    public List<String> getPreviouslyInvalidatedApiKeyTemplates() {
        return previouslyInvalidatedApiKeyTemplates;
    }

    public List<ElasticsearchException> getErrors() {
        return errors;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
            .array("invalidated_api_key_templates", invalidatedApiKeyTemplates.toArray(Strings.EMPTY_ARRAY))
            .array("previously_invalidated_api_key_templates", previouslyInvalidatedApiKeyTemplates.toArray(Strings.EMPTY_ARRAY))
            .field("error_count", errors.size());
        if (errors.isEmpty() == false) {
            builder.field("error_details");
            builder.startArray();
            for (ElasticsearchException e : errors) {
                builder.startObject();
                ElasticsearchException.generateThrowableXContent(builder, params, e);
                builder.endObject();
            }
            builder.endArray();
        }
        return builder.endObject();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeStringCollection(invalidatedApiKeyTemplates);
        out.writeStringCollection(previouslyInvalidatedApiKeyTemplates);
        out.writeCollection(errors, StreamOutput::writeException);
    }

    @SuppressWarnings("unchecked")
    static final ConstructingObjectParser<InvalidateApiKeyTemplateResponse, Void> PARSER = new ConstructingObjectParser<>(
        "invalidate_api_key_response",
        args -> {
            return new InvalidateApiKeyTemplateResponse((List<String>) args[0], (List<String>) args[1], (List<ElasticsearchException>) args[3]);
        }
    );
    static {
        PARSER.declareStringArray(constructorArg(), new ParseField("invalidated_api_key_templates"));
        PARSER.declareStringArray(constructorArg(), new ParseField("previously_invalidated_api_key_templates"));
        // we parse error_count but ignore it while constructing response
        PARSER.declareInt(constructorArg(), new ParseField("error_count"));
        PARSER.declareObjectArray(optionalConstructorArg(), (p, c) -> ElasticsearchException.fromXContent(p),
                new ParseField("error_details"));
    }

    public static InvalidateApiKeyTemplateResponse fromXContent(XContentParser parser) throws IOException {
        return PARSER.parse(parser, null);
    }

    @Override
    public String toString() {
        return "InvalidateApiKeyTemplateResponse [invalidatedApiKeyTemplates=" + invalidatedApiKeyTemplates + ", previouslyInvalidatedApiKeys="
                + previouslyInvalidatedApiKeyTemplates + ", errors=" + errors + "]";
    }

}
