/*
 * Copyright (c) 2024-2026 European Commission
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

import eu.europa.ec.eudi.iso18013.transfer.asMap
import eu.europa.ec.eudi.iso18013.transfer.generateDeviceResponse
import eu.europa.ec.eudi.iso18013.transfer.internal.assertAgeOverRequestLimitForIso18013
import eu.europa.ec.eudi.iso18013.transfer.internal.filterWithRequestedDocuments
import eu.europa.ec.eudi.iso18013.transfer.internal.getValidIssuedMsoMdocDocumentById
import eu.europa.ec.eudi.iso18013.transfer.response.DisclosedDocument
import eu.europa.ec.eudi.iso18013.transfer.response.DisclosedDocuments
import eu.europa.ec.eudi.iso18013.transfer.response.RequestProcessor
import eu.europa.ec.eudi.iso18013.transfer.response.RequestedDocuments
import eu.europa.ec.eudi.iso18013.transfer.response.ResponseResult
import eu.europa.ec.eudi.wallet.document.DocumentId
import eu.europa.ec.eudi.wallet.document.DocumentManager
import eu.europa.ec.eudi.wallet.document.IssuedDocument
import kotlinx.coroutines.runBlocking
import kotlinx.io.bytestring.ByteString
import org.multipaz.crypto.Algorithm
import org.multipaz.mdoc.credential.MdocCredential
import org.multipaz.mdoc.response.DeviceResponseGenerator
import org.multipaz.util.Constants
import kotlin.time.ExperimentalTime

/**
 * Implementation of [RequestProcessor.ProcessedRequest.Success] for [DeviceRequest].
 * @property documentManager the document manager to use for resolving documents
 * @property sessionTranscript the session transcript
 * @property requestedDocuments the requested documents
 * @property includeOnlyRequested whether to include only the requested documents or all the disclosed documents. Default is true.
 */
class ProcessedDeviceRequest(
    private val documentManager: DocumentManager,
    private val sessionTranscript: ByteArray,
    requestedDocuments: RequestedDocuments
) : RequestProcessor.ProcessedRequest.Success(requestedDocuments) {

    var includeOnlyRequested: Boolean = true

    /**
     * Generate the response for the disclosed documents.
     * @param disclosedDocuments the disclosed documents
     * @param signatureAlgorithm not used - the credential's key is used for signing the document responses
     * @return the response result with the device response or the error
     */
    @OptIn(ExperimentalTime::class)
    override fun generateResponse(
        disclosedDocuments: DisclosedDocuments,
        signatureAlgorithm: Algorithm?
    ): ResponseResult = runBlocking {
        try {
            val filteredDocuments = filterDocumentsIfNeeded(disclosedDocuments)
            val deviceResponseGenerator =
                DeviceResponseGenerator(Constants.DEVICE_RESPONSE_STATUS_OK)
            val documentIds = mutableListOf<DocumentId>()

            filteredDocuments.forEach { disclosedDocument ->
                processDisclosedDocument(disclosedDocument, deviceResponseGenerator)
                documentIds.add(disclosedDocument.documentId)
            }

            ResponseResult.Success(
                DeviceResponse(
                    deviceResponseBytes = deviceResponseGenerator.generate(),
                    sessionTranscriptBytes = sessionTranscript,
                    documentIds = documentIds
                )
            )
        } catch (e: Exception) {
            ResponseResult.Failure(e)
        }
    }

    /**
     * Filters the disclosed documents based on the [includeOnlyRequested] flag.
     * If [includeOnlyRequested] is true, only documents that match the requested documents are returned.
     * Otherwise, all disclosed documents are returned.
     *
     * @param disclosedDocuments the documents disclosed by the user
     * @return filtered documents if [includeOnlyRequested] is true, otherwise all disclosed documents
     */
    private fun filterDocumentsIfNeeded(disclosedDocuments: DisclosedDocuments): DisclosedDocuments {
        return if (includeOnlyRequested) {
            disclosedDocuments.filterWithRequestedDocuments(requestedDocuments)
        } else {
            disclosedDocuments
        }
    }

    /**
     * Processes a single disclosed document and adds it to the device response generator.
     * First attempts to add the document as a ZK proof document if applicable (without consuming the credential).
     * If ZK processing is not available or fails, adds it as a regular document,
     * applying the [eu.europa.ec.eudi.wallet.document.CreateDocumentSettings.CredentialPolicy] to enforce usage limits.
     *
     * @param disclosedDocument the document to process
     * @param deviceResponseGenerator the generator to add the processed document to
     * @throws IllegalStateException if the document is not valid or cannot be processed
     */
    private suspend fun processDisclosedDocument(
        disclosedDocument: DisclosedDocument,
        deviceResponseGenerator: DeviceResponseGenerator
    ) {
        val issuedDocument = documentManager
            .getValidIssuedMsoMdocDocumentById(disclosedDocument.documentId)
            .assertAgeOverRequestLimitForIso18013(disclosedDocument)

        if (tryAddZkDocument(issuedDocument, disclosedDocument, deviceResponseGenerator)) {
            return
        }

        addDocument(issuedDocument, disclosedDocument, deviceResponseGenerator)
    }

    /**
     * Attempts to add the document as a zero-knowledge proof document to the response.
     * Uses [IssuedDocument.findCredential] to retrieve the credential without consuming it,
     * bypassing the [eu.europa.ec.eudi.wallet.document.CreateDocumentSettings.CredentialPolicy] checks.
     * This allows generating the device response for ZK proof creation without affecting
     * the credential's usage counter or applying usage limits.
     *
     * @param issuedDocument the issued document from the document manager
     * @param disclosedDocument the document with disclosed items to include in the response
     * @param deviceResponseGenerator the generator to add the ZK document to
     * @return true if the document was successfully added as a ZK document, false otherwise
     */
    @OptIn(ExperimentalTime::class)
    private suspend fun tryAddZkDocument(
        issuedDocument: IssuedDocument,
        disclosedDocument: DisclosedDocument,
        deviceResponseGenerator: DeviceResponseGenerator
    ): Boolean {
        return try {
            val matchedZkSystem = requestedDocuments
                .find { it.documentId == disclosedDocument.documentId }
                ?.matchedZkSystem
                ?: return false

            val credential = checkNotNull(issuedDocument.findCredential()) {
                "No credential found in the issued document for ZK proof generation"
            }
            check(credential is MdocCredential) {
                "Credential is not of type MdocCredential for ZK proof generation"
            }

            val encodedDocument = credential.generateDeviceResponse(
                sessionTranscript = sessionTranscript,
                elements = disclosedDocument.disclosedItems.asMap(),
                keyUnlockData = disclosedDocument.keyUnlockData
            )

            val zkDocument = matchedZkSystem.system.generateProof(
                zkSystemSpec = matchedZkSystem.spec,
                encodedDocument = ByteString(encodedDocument),
                encodedSessionTranscript = ByteString(sessionTranscript)
            )
            deviceResponseGenerator.addZkDocument(zkDocument)
            true
        } catch (_: Throwable) {
            false
        }
    }

    /**
     * Adds a non-ZK document to the device response generator.
     * Uses [IssuedDocument.consumingCredential] to retrieve and consume the credential,
     * which applies the [eu.europa.ec.eudi.wallet.document.CreateDocumentSettings.CredentialPolicy]
     * to enforce usage limits and track credential consumption.
     * Generates the device response with the disclosed items and adds it to the generator.
     *
     * @param issuedDocument the issued document from the document manager
     * @param disclosedDocument the document with disclosed items to include in the response
     * @param deviceResponseGenerator the generator to add the document to
     * @throws IllegalStateException if the credential is not of type MdocCredential
     * @throws IllegalStateException if credential consumption fails or policy limits are exceeded
     */
    private suspend fun addDocument(
        issuedDocument: IssuedDocument,
        disclosedDocument: DisclosedDocument,
        deviceResponseGenerator: DeviceResponseGenerator
    ) {
        val encodedDocument = issuedDocument.consumingCredential {
            check(this is MdocCredential) {
                "Credential must be of type MdocCredential"
            }
            generateDeviceResponse(
                sessionTranscript = sessionTranscript,
                elements = disclosedDocument.disclosedItems.asMap(),
                keyUnlockData = disclosedDocument.keyUnlockData
            )
        }.getOrThrow()
        deviceResponseGenerator.addDocument(encodedDocument)
    }
}