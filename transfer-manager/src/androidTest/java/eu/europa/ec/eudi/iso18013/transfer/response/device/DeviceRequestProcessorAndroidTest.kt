/*
 * Copyright (c) 2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package eu.europa.ec.eudi.iso18013.transfer.response.device

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import eu.europa.ec.eudi.iso18013.transfer.createDocumentManager
import eu.europa.ec.eudi.iso18013.transfer.createZkSystemRepository
import eu.europa.ec.eudi.iso18013.transfer.response.DisclosedDocument
import eu.europa.ec.eudi.iso18013.transfer.response.DisclosedDocuments
import eu.europa.ec.eudi.iso18013.transfer.response.ResponseResult
import eu.europa.ec.eudi.iso18013.transfer.toDocItems
import eu.europa.ec.eudi.wallet.document.IssuedDocument
import eu.europa.ec.eudi.wallet.document.format.MsoMdocData
import eu.europa.ec.eudi.wallet.document.format.MsoMdocFormat
import kotlinx.coroutines.test.runTest
import org.junit.Assert
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.toDataItem
import org.multipaz.mdoc.request.DocRequestInfo
import org.multipaz.mdoc.request.ZkRequest
import org.multipaz.mdoc.request.buildDeviceRequest

@RunWith(AndroidJUnit4::class)
class DeviceRequestProcessorAndroidTest {
    companion object {

        private lateinit var context: Context

        @BeforeClass
        @JvmStatic
        fun setup() {
            context = InstrumentationRegistry.getInstrumentation().targetContext
        }
    }

    @Test
    fun processed_request_should_add_zk_response_if_matched_circuit_for_document() = runTest {
        val documentManager = createDocumentManager(context, null)
        val zkSystemRepository = createZkSystemRepository(context)
        val sessionTranscript = byteArrayOf(0)
        val requestWithZk = DeviceRequest(
            deviceRequestBytes = Cbor.encode(
                buildDeviceRequest(
                    sessionTranscript = sessionTranscript.toDataItem(),
                ) {
                    addDocRequest(
                        docType = "eu.europa.ec.av.1",
                        nameSpaces = mapOf(
                            "eu.europa.ec.av.1" to mapOf(
                                "age_over_18" to false,
                            )
                        ),
                        docRequestInfo = DocRequestInfo(
                            zkRequest = ZkRequest(
                                systemSpecs = zkSystemRepository.getAllZkSystemSpecs(),
                                zkRequired = true,
                            )
                        )
                    )
                }.toDataItem()
            ),
            sessionTranscriptBytes = sessionTranscript
        )

        val requestProcessor =
            DeviceRequestProcessor(documentManager, zkSystemRepository = zkSystemRepository)
        val processedRequest = requestProcessor.process(requestWithZk)

        val expectedDocument = documentManager.getDocuments()
            .filterIsInstance<IssuedDocument>()
            .first {(it.format as? MsoMdocFormat)?.docType == "eu.europa.ec.av.1" }


        val responseResult = processedRequest.getOrThrow().generateResponse(
            disclosedDocuments = DisclosedDocuments(
                DisclosedDocument(
                    documentId = expectedDocument.id,
                    disclosedItems = (expectedDocument.data as MsoMdocData).nameSpaces.toDocItems(),
                    keyUnlockData = null,
                )
            ),
            signatureAlgorithm = null,
        )

        Assert.assertTrue(responseResult is ResponseResult.Success)

        val responseCbor = Cbor.decode((responseResult.getOrThrow() as DeviceResponse).deviceResponseBytes).asMap
        Assert.assertTrue(responseCbor.containsKey("zkDocuments".toDataItem()))
        Assert.assertFalse(responseCbor.containsKey("documents".toDataItem()))
    }
}