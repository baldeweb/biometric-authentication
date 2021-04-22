package com.example.android.biometricauth

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProperties.KEY_ALGORITHM_AES
import java.io.IOException
import java.security.*
import java.security.cert.CertificateException
import javax.crypto.*

class KeyStoreUtils {
    companion object {
        /**
         * Tries to encrypt some data with the generated key from [createKey]. This only works if the
         * user just authenticated via fingerprint.
         */
        fun tryEncrypt(cipher: Cipher, onSuccess: (cipher: Cipher) -> Unit, onError: (Exception) -> Unit) {
            try {
                onSuccess.invoke(cipher)
            } catch (e: Exception) {
                when (e) {
                    is BadPaddingException,
                    is IllegalBlockSizeException -> {
                        onError.invoke(e)
                    }
                    else -> throw e
                }
            }
        }

        fun createKey(keyStore: KeyStore, keyGenerator: KeyGenerator, keyName: String, invalidatedByBiometricEnrollment: Boolean) {
            // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
            // for your flow. Use of keys is necessary if you need to know if the set of enrolled
            // fingerprints has changed.
            try {
                keyStore.load(null)
                keyGenerator.apply {
                    init(KeyGenParameterSpec.Builder(keyName, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                            .setUserAuthenticationRequired(true)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                            .setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment)
                            .build()
                    )
                    generateKey()
                }
            } catch (e: Exception) {
                when (e) {
                    is NoSuchAlgorithmException,
                    is InvalidAlgorithmParameterException,
                    is CertificateException,
                    is IOException -> throw RuntimeException(e)
                    else -> throw e
                }
            }
        }

        fun setupKeyStoreAndKeyGenerator(keyStoreKey: String, keyStore: (KeyStore) -> Unit, keyGenerator: (KeyGenerator) -> Unit) {
            try {
                keyStore.invoke(KeyStore.getInstance(keyStoreKey))
            } catch (e: KeyStoreException) {
                throw RuntimeException("Failed to get an instance of KeyStore", e)
            }

            try {
                keyGenerator.invoke(KeyGenerator.getInstance(KEY_ALGORITHM_AES, keyStoreKey))
            } catch (e: Exception) {
                when (e) {
                    is NoSuchAlgorithmException,
                    is NoSuchProviderException ->
                        throw RuntimeException("Failed to get an instance of KeyGenerator", e)
                    else -> throw e
                }
            }
        }
    }
}