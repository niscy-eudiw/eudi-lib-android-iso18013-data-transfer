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
 * Doc item represents a data element
 *
 * @property elementIdentifier the data element identifier e.g. family_name, given_name
 */
open class DocItem(
    open val elementIdentifier: String
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DocItem) return false

        if (elementIdentifier != other.elementIdentifier) return false

        return true
    }

    override fun hashCode(): Int {
        return elementIdentifier.hashCode()
    }
}