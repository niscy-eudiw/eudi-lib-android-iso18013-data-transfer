/*
 * Copyright (c) 2023-2025 European Commission
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
package eu.europa.ec.eudi.iso18013.transfer.internal.readerauth

import android.util.Log
import eu.europa.ec.eudi.iso18013.transfer.internal.readerauth.crl.CertificateCRLValidation
import eu.europa.ec.eudi.iso18013.transfer.internal.readerauth.crl.CertificateCRLValidationException
import eu.europa.ec.eudi.iso18013.transfer.internal.readerauth.profile.ProfileValidation
import eu.europa.ec.eudi.iso18013.transfer.readerauth.ReaderTrustStore
import org.bouncycastle.asn1.x500.X500Name
import java.security.InvalidAlgorithmParameterException
import java.security.NoSuchAlgorithmException
import java.security.cert.CertPathValidator
import java.security.cert.CertPathValidatorException
import java.security.cert.CertStore
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.PKIXCertPathValidatorResult
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.util.Date

internal class ReaderTrustStoreImpl(
    private val trustedCertificates: List<X509Certificate>,
    private val profileValidation: ProfileValidation,
) : ReaderTrustStore {

    private val trustedCertMap: Map<X500Name, X509Certificate> by lazy {
        trustedCertificates.associateBy { X500Name(it.subjectX500Principal.name) }
    }

    override fun createCertificationTrustPath(chain: List<X509Certificate>): List<X509Certificate>? {
        for (certificate in chain) {
            val x500Name = X500Name(certificate.issuerX500Principal.name)
            trustedCertMap[x500Name]?.let {
                return listOf(certificate, it)
            }
        }
        return null
    }

    /**
     * Validates the certification trust path of a document signer.
     *
     * This function verifies the certificate chain against a set of trusted certificates
     * and performs additional profile validation on the signer's certificate.
     *
     * @param chainToDocumentSigner The certificate chain leading to the document signer's certificate.
     * @return `true` if the certification trust path is valid, `false` otherwise.
     */
    override fun validateCertificationTrustPath(chainToDocumentSigner: List<X509Certificate>): Boolean {

        val certificate = chainToDocumentSigner.lastOrNull() ?: return false
        var result = false

        for (cert in chainToDocumentSigner) {
            try {
                val certificateList = arrayListOf(cert, *trustedCertificates.toTypedArray())

                val certStore = CertStore.getInstance(
                    "Collection",
                    CollectionCertStoreParameters(certificateList),
                )
                val certificateFactory = CertificateFactory.getInstance("X.509")

                val certPath = certificateFactory.generateCertPath(arrayListOf(cert))
                val trustAnchors = trustedCertificates.map { c ->
                    TrustAnchor(c, null)
                }.toSet()

                val validator = CertPathValidator.getInstance("PKIX")
                val param = PKIXParameters(trustAnchors).apply {
                    isRevocationEnabled = false
                    addCertStore(certStore)
                    date = Date()
                }

                // Path Validation
                val certPathValidationResult =
                    validator.validate(certPath, param) as PKIXCertPathValidatorResult
                val trustAnchor = certPathValidationResult.trustAnchor

                CertificateCRLValidation.verify(cert)

                trustAnchor.trustedCert?.let { trustedCert ->
                    CertificateCRLValidation.verify(trustedCert)
                    if (cert == certificate) {
                        result = profileValidation.validate(cert, trustedCert)
                    }
                }

            } catch (e: Exception) {
                when (e) {
                    is InvalidAlgorithmParameterException ->
                        Log.d(TAG, "INVALID_ALGORITHM_PARAMETER", e)

                    is NoSuchAlgorithmException -> Log.d(TAG, "NO_SUCH_ALGORITHM", e)
                    is CertificateException -> Log.d(TAG, "CERTIFICATE_ERROR", e)
                    is CertPathValidatorException -> Log.d(TAG, "CERTIFICATE_PATH_ERROR", e)
                    is CertificateCRLValidationException -> Log.d(TAG, "CERTIFICATE_REVOKED", e)
                    else -> Log.d(TAG, "UNKNOWN_ERROR", e)
                }
            }
        }
        return result
    }

    companion object {
        private const val TAG = "ReaderTrustStoreImpl"
    }
}
