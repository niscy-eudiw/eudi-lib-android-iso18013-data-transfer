/*
 * Copyright (c) 2024 European Commission
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

package eu.europa.ec.eudi.iso18013.transfer.response

import eu.europa.ec.eudi.iso18013.transfer.IntentToRetain
import eu.europa.ec.eudi.wallet.document.DocumentId

/**
 * Represents a request received by a verifier and contains the requested documents and elements
 *
 * @property documentId the unique id of the document stored in identity credential api
 * @property requestedItems the list of requested items
 * @property readerAuth the result of the reader authentication
 */

data class RequestedDocument(
    val documentId: DocumentId,
    val requestedItems: Map<DocItem, IntentToRetain>,
    val readerAuth: ReaderAuth?
)