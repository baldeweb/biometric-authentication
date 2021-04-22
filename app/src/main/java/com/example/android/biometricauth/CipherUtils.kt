package com.example.android.biometricauth

import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import com.example.android.biometricauth.KeyStoreUtils.Companion.createKey
import java.io.IOException
import java.security.*
import java.security.cert.CertificateException
import javax.crypto.Cipher
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey

class CipherUtils {
    companion object {
        /**
         * Initialize the [Cipher] instance with the created key in the [createKey] method.
         *
         * @param keyName the key name to init the cipher
         * @return `true` if initialization succeeded, `false` if the lock screen has been disabled or
         * reset after key generation, or if a fingerprint was enrolled after key generation.
         */
        fun initCipher(keyStore: KeyStore, cipher: Cipher, keyName: String): Boolean {
            try {
                keyStore.load(null)
                cipher.init(Cipher.ENCRYPT_MODE, keyStore.getKey(keyName, null) as SecretKey)
                return true
            } catch (e: Exception) {
                when (e) {
                    is KeyPermanentlyInvalidatedException -> return false
                    is KeyStoreException,
                    is CertificateException,
                    is UnrecoverableKeyException,
                    is IOException,
                    is NoSuchAlgorithmException,
                    is InvalidKeyException -> throw RuntimeException("Failed to init Cipher", e)
                    else -> throw e
                }
            }
        }
        /**
         * Sets up default cipher and a non-invalidated cipher
         */
        fun setupCiphers(): Pair<Cipher, Cipher> {
            val defaultCipher: Cipher
            val cipherNotInvalidated: Cipher
            try {
                val cipherString = "${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_CBC}/${KeyProperties.ENCRYPTION_PADDING_PKCS7}"
                defaultCipher = Cipher.getInstance(cipherString)
                cipherNotInvalidated = Cipher.getInstance(cipherString)
            } catch (e: Exception) {
                when (e) {
                    is NoSuchAlgorithmException,
                    is NoSuchPaddingException ->
                        throw RuntimeException("Failed to get an instance of Cipher", e)
                    else -> throw e
                }
            }
            return Pair(defaultCipher, cipherNotInvalidated)
        }
    }
}