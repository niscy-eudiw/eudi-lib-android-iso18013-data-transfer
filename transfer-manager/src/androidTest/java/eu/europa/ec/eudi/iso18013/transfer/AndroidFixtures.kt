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
package eu.europa.ec.eudi.iso18013.transfer

import android.content.Context
import eu.europa.ec.eudi.wallet.document.CreateDocumentSettings
import eu.europa.ec.eudi.wallet.document.DocumentManager
import eu.europa.ec.eudi.wallet.document.DocumentManagerImpl
import eu.europa.ec.eudi.wallet.document.sample.SampleDocumentManagerImpl
import kotlinx.io.bytestring.ByteString
import org.multipaz.mdoc.zkp.ZkSystemRepository
import org.multipaz.mdoc.zkp.longfellow.LongfellowZkSystem
import org.multipaz.securearea.PassphraseConstraints
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.securearea.software.SoftwareCreateKeySettings
import org.multipaz.securearea.software.SoftwareSecureArea
import org.multipaz.storage.ephemeral.EphemeralStorage
import org.multipaz.util.fromHex
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.ExperimentalTime

@OptIn(ExperimentalEncodingApi::class, ExperimentalTime::class)
suspend fun createDocumentManager(context: Context, keyLockPassphrase: String?): DocumentManager {
    val storage = EphemeralStorage()
    val secureArea = SoftwareSecureArea.create(storage)
    val secureAreaRep = SecureAreaRepository.Builder()
        .add(secureArea)
        .build()
    return SampleDocumentManagerImpl(
        DocumentManagerImpl(
            identifier = "DocumentManager",
            storage = storage,
            secureAreaRepository = secureAreaRep,
            ktorHttpClientFactory = null,
        )
    ).apply {
        loadMdocSampleDocuments(
            sampleData = String(
                context.assets.open("sample_documents.txt").readAllBytes()
            ).fromHex(),
            createSettings = CreateDocumentSettings(
                secureAreaIdentifier = secureArea.identifier,
                createKeySettings = keyLockPassphrase?.let { p ->
                    SoftwareCreateKeySettings.Builder()
                        .setPassphraseRequired(
                            true,
                            p,
                            PassphraseConstraints.PIN_FOUR_DIGITS
                        )
                        .build()
                } ?: SoftwareCreateKeySettings.Builder().build(),
            ),
            documentNamesMap = mapOf(
                "eu.europa.ec.av.1" to "AgeVerification"
            )
        ).getOrThrow()
    }
}


fun createZkSystemRepository(context: Context): ZkSystemRepository {
    val zkSystemRepository = ZkSystemRepository()
        .apply {
            val circuitsToAdd = listOf(
                "longfellow-libzk-v1/6_1_4096_2945_137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6",
            )
            val longfellowSystem = LongfellowZkSystem()
            for (circuit in circuitsToAdd) {
                val circuitBytes = ByteString(context.assets.open(circuit).readAllBytes())
                val pathParts = circuit.split("/")
                longfellowSystem.addCircuit(pathParts[pathParts.size - 1], circuitBytes)
            }
            add(longfellowSystem)
        }

    return zkSystemRepository
}