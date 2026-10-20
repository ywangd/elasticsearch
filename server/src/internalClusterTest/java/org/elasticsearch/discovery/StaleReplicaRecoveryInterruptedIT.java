/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

package org.elasticsearch.discovery;

import org.elasticsearch.action.admin.cluster.allocation.ClusterAllocationExplainRequest;
import org.elasticsearch.action.admin.cluster.allocation.ClusterAllocationExplanation;
import org.elasticsearch.action.admin.cluster.allocation.TransportClusterAllocationExplainAction;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.cluster.routing.UnassignedInfo;
import org.elasticsearch.cluster.routing.allocation.NodeAllocationResult;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.indices.recovery.PeerRecoverySourceService;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.test.disruption.NetworkDisruption;
import org.elasticsearch.test.disruption.NetworkDisruption.TwoPartitions;
import org.elasticsearch.test.transport.MockTransportService;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.elasticsearch.test.hamcrest.ElasticsearchAssertions.assertAcked;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

/**
 * Reproduces the data loss seen in an HA deployment (1 primary + 1 replica, 2 data/master-eligible nodes and a tiebreaker) when an AZ
 * went down in two steps:
 * <ol>
 *     <li>The link between the master (holding the primary) and the other data node breaks. The master removes the node from the
 *     cluster. No further indexing takes place.</li>
 *     <li>The link heals, the node rejoins and its replica is re-initialized with a new allocation id and starts a peer recovery from the
 *     primary. This recovery has not completed (so the new id is not in-sync) when the master node is lost for good.</li>
 * </ol>
 * The surviving copy is stale so the primary cannot be allocated and the index stays red, even though a replica existed.
 */
@ESIntegTestCase.ClusterScope(scope = ESIntegTestCase.Scope.TEST, numDataNodes = 0)
public class StaleReplicaRecoveryInterruptedIT extends AbstractDisruptionTestCase {

    public void testPrimaryUnassignedDueToStaleCopyWhenMasterLostDuringReplicaRecovery() throws Exception {
        final String indexName = "test";

        // The first node is the elected master and holds the primary.
        final String primaryNode = internalCluster().startNode();
        assertAcked(
            prepareCreate(indexName).setSettings(
                Settings.builder()
                    .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
                    .put(IndexMetadata.SETTING_NUMBER_OF_REPLICAS, 0)
                    .put(IndexMetadata.INDEX_ROUTING_REQUIRE_GROUP_PREFIX + "._name", primaryNode)
            )
        );
        indexRandom(true, prepareIndex(indexName).setSource("field", "before"));

        // The tiebreaker is master-eligible only; the replica node is both master-eligible and data.
        internalCluster().startMasterOnlyNode();
        final String replicaNode = internalCluster().startNode();
        ensureStableCluster(3);
        assertThat(internalCluster().getMasterName(), equalTo(primaryNode));

        updateIndexSettings(
            Settings.builder()
                .put(IndexMetadata.SETTING_NUMBER_OF_REPLICAS, 1)
                .putNull(IndexMetadata.INDEX_ROUTING_REQUIRE_GROUP_PREFIX + "._name"),
            indexName
        );
        ensureGreen(indexName);
        final String staleAllocationId = getNodeClusterState(primaryNode).routingTable()
            .index(indexName)
            .shard(0)
            .replicaShards()
            .get(0)
            .allocationId()
            .getId();

        // Step 1: break the link between primary(master) and replica. The tiebreaker still sees both so the master stays in place.
        final NetworkDisruption disruption = new NetworkDisruption(
            new TwoPartitions(primaryNode, replicaNode),
            NetworkDisruption.DISCONNECT
        );
        setDisruptionScheme(disruption);
        disruption.startDisrupting();

        assertBusy(() -> assertThat(getNodeClusterState(primaryNode).nodes().getDataNodes().size(), equalTo(1)));

        // No writes happen while the replica is gone, so its allocation id is still in the in-sync set. Staleness comes solely from the
        // replica being re-initialized under a new allocation id on rejoin.
        assertThat(
            getNodeClusterState(primaryNode).metadata().getProject().index(indexName).inSyncAllocationIds(0).contains(staleAllocationId),
            is(true)
        );

        // Step 2: heal the link and hold the replica's peer recovery on the primary so that it can never complete.
        final CountDownLatch recoveryStarted = new CountDownLatch(1);
        MockTransportService.getInstance(primaryNode)
            .addRequestHandlingBehavior(PeerRecoverySourceService.Actions.START_RECOVERY, (handler, request, channel, task) -> {
                // drop the request, the recovery on the replica node never completes
                recoveryStarted.countDown();
            });
        disruption.stopDisrupting();
        assertTrue("replica recovery did not start", recoveryStarted.await(30, TimeUnit.SECONDS));

        // The master (and holder of the only in-sync copy) is lost for good.
        internalCluster().stopNode(primaryNode);

        // The remaining replica copy is not in-sync, so the primary must not be allocated.
        assertBusy(() -> {
            final ClusterState state = getNodeClusterState(replicaNode);
            assertNotNull(state.nodes().getMasterNode());
            assertTrue(state.routingTable().index(indexName).shard(0).primaryShard().unassigned());
        });
        final ClusterAllocationExplanation explanation = client(replicaNode).execute(
            TransportClusterAllocationExplainAction.TYPE,
            new ClusterAllocationExplainRequest(TEST_REQUEST_TIMEOUT).setIndex(indexName).setShard(0).setPrimary(true)
        ).actionGet().getExplanation();
        assertThat(
            explanation.getShardAllocationDecision().getAllocateDecision().getAllocationStatus(),
            equalTo(UnassignedInfo.AllocationStatus.NO_VALID_SHARD_COPY)
        );
        final NodeAllocationResult replicaNodeResult = explanation.getShardAllocationDecision()
            .getAllocateDecision()
            .getNodeDecisions()
            .stream()
            .filter(r -> r.getNode().getName().equals(replicaNode))
            .findFirst()
            .orElseThrow();
        assertThat(replicaNodeResult.getShardStoreInfo().isInSync(), is(false));
        assertThat(replicaNodeResult.getShardStoreInfo().getAllocationId(), not(equalTo(null)));
    }

    @Override
    protected void beforeIndexDeletion() {
        // The index is intentionally left red with its primary lost, so the consistency checks on all shard copies cannot apply.
    }
}
