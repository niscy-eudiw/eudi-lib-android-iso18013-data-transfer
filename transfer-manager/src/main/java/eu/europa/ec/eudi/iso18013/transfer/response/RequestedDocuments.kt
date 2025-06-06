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

/**
 * Wrapper class that contains the requested documents
 *
 * @param documents the list of requested documents
 */
class RequestedDocuments(documents: List<RequestedDocument>) :
    List<RequestedDocument> by documents {

    /**
     * Constructor that takes a vararg of [RequestedDocument] and converts it to a list
     * @param documents the list of requested documents
     */
    constructor(vararg documents: RequestedDocument) : this(documents.toList())
}