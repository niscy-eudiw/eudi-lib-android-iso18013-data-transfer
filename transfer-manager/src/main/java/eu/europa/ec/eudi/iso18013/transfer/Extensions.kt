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

/**
 * Extension functions for ISO 18013 data transfer operations.
 * Provides utilities for converting between different data representations,
 * generating device responses, and working with mdoc credentials.
 */
@file:JvmName("Extensions")

package eu.europa.ec.eudi.iso18013.transfer

import eu.europa.ec.eudi.iso18013.transfer.internal.asProvider
import eu.europa.ec.eudi.iso18013.transfer.response.DocItem
import eu.europa.ec.eudi.iso18013.transfer.response.RequestProcessor
import eu.europa.ec.eudi.iso18013.transfer.response.ResponseResult
import eu.europa.ec.eudi.iso18013.transfer.response.device.MsoMdocItem
import eu.europa.ec.eudi.wallet.document.ElementIdentifier
import eu.europa.ec.eudi.wallet.document.NameSpace
import eu.europa.ec.eudi.wallet.document.credential.CredentialIssuedData
import eu.europa.ec.eudi.wallet.document.credential.getIssuedData
import kotlinx.coroutines.withContext
import org.multipaz.document.DocumentRequest
import org.multipaz.document.NameSpacedData
import org.multipaz.mdoc.credential.MdocCredential
import org.multipaz.mdoc.response.DocumentGenerator
import org.multipaz.mdoc.util.MdocUtil
import org.multipaz.securearea.KeyUnlockData
import org.multipaz.securearea.UnlockReason

/**
 * Converts a list of document items to a map of namespaces to element identifiers.
 * Only processes [MsoMdocItem] instances, filtering out any other [DocItem] types.
 * Groups the items by namespace and maps each namespace to its list of element identifiers.
 *
 * @receiver the list of [DocItem] to convert
 * @return a map where keys are namespaces and values are lists of element identifiers
 */
@JvmName("docItemsToNameSpaces")
fun List<DocItem>.asMap(): Map<NameSpace, List<ElementIdentifier>> = this
    .filterIsInstance<MsoMdocItem>()
    .groupBy { (nameSpace, _) -> nameSpace }
    .mapValues { (_, docItems) -> docItems.map { it.elementIdentifier } }

/**
 * Converts a map of namespaces to element identifiers into a list of document items.
 * Creates [MsoMdocItem] instances for each namespace-element identifier pair.
 *
 * @receiver the map of namespaces to element identifier lists to convert
 * @return a flat list of [MsoMdocItem] instances representing all namespace-element pairs
 */
@JvmName("nameSpacesToDocItems")
fun Map<NameSpace, List<ElementIdentifier>>.toDocItems(): List<DocItem> =
    this.flatMap { (nameSpace, elementIdentifiers) ->
        elementIdentifiers.map { elementIdentifier ->
            MsoMdocItem(
                namespace = nameSpace,
                elementIdentifier = elementIdentifier
            )
        }
    }

/**
 * Converts a processed request result to a Kotlin [Result] type.
 * Success cases are wrapped in [Result.success], while failure cases
 * are wrapped in [Result.failure] with the error as the cause.
 *
 * @receiver the [RequestProcessor.ProcessedRequest] to convert
 * @return a [Result] containing either the success value or the failure error
 */
fun RequestProcessor.ProcessedRequest.toKotlinResult(): Result<RequestProcessor.ProcessedRequest.Success> {
    return when (this) {
        is RequestProcessor.ProcessedRequest.Success -> Result.success(this)
        is RequestProcessor.ProcessedRequest.Failure -> Result.failure(this.error)
    }
}

/**
 * Converts a response result to a Kotlin [Result] type.
 * Success cases are wrapped in [Result.success], while failure cases
 * are wrapped in [Result.failure] with the throwable as the cause.
 *
 * @receiver the [ResponseResult] to convert
 * @return a [Result] containing either the success value or the failure throwable
 */
fun ResponseResult.toKotlinResult(): Result<ResponseResult.Success> {
    return when (this) {
        is ResponseResult.Success -> Result.success(this)
        is ResponseResult.Failure -> Result.failure(this.throwable)
    }
}

/**
 * Generates a device response for an mdoc credential.
 * This function creates a signed device response containing the requested data elements
 * from the credential, using the credential's key for signing.
 *
 * The function retrieves the credential's issued data, merges the requested elements with
 * the issuer namespaces, and generates a signed response using the credential's secure area.
 *
 * @receiver the [MdocCredential] to generate the response from
 * @param sessionTranscript the session transcript bytes that bind the response to the current session
 * @param elements optional map of namespaces to element identifiers to include in the response.
 *                 If null, all available elements from the credential will be included.
 * @param keyUnlockData optional unlock data required to access the credential's signing key
 * @return the generated device response as a byte array
 * @throws IllegalStateException if the credential data cannot be retrieved or the response generation fails
 */
suspend fun MdocCredential.generateDeviceResponse(
    sessionTranscript: ByteArray,
    elements: Map<NameSpace, List<ElementIdentifier>>? = null,
    keyUnlockData: KeyUnlockData?
): ByteArray {
    val provider = keyUnlockData.asProvider()

    return withContext(provider) {

        val credentialIssuedData = getIssuedData<CredentialIssuedData.MsoMdoc>()
        val (nameSpacedData, staticAuthData) = credentialIssuedData.getOrThrow()
        val elements = elements ?: nameSpacedData.nameSpaceNames.associateWith {
            nameSpacedData.getDataElementNames(it)
        }
        val dataElements = elements.flatMap { (nameSpace, identifiers) ->
            identifiers.map { identifier ->
                DocumentRequest.DataElement(nameSpace, identifier, false)
            }
        }
        val request = DocumentRequest(dataElements)

        val mergedIssuerNamespaces = MdocUtil.mergeIssuerNamesSpaces(
            request, nameSpacedData, staticAuthData
        )

        DocumentGenerator(docType, staticAuthData.issuerAuth, sessionTranscript)
            .setIssuerNamespaces(mergedIssuerNamespaces)
            .setDeviceNamespacesSignature(
                dataElements = NameSpacedData.Builder().build(),
                secureArea = secureArea,
                keyAlias = alias,
                unlockReason = UnlockReason.Unspecified
            )
            .generate()
    }
}