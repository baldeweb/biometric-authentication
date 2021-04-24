package com.example.android.biometricauth

import android.content.SharedPreferences
import android.os.Bundle
import android.security.keystore.KeyProperties.*
import android.util.Base64
import android.util.Log
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS
import androidx.biometric.BiometricPrompt
import androidx.preference.PreferenceManager
import com.example.android.biometricauth.BiometricUtils.Companion.createBiometricPrompt
import com.example.android.biometricauth.BiometricUtils.Companion.createPromptInfo
import com.example.android.biometricauth.CipherUtils.Companion.initCipher
import com.example.android.biometricauth.CipherUtils.Companion.setupCiphers
import com.example.android.biometricauth.KeyStoreUtils.Companion.setupKeyStoreAndKeyGenerator
import com.example.android.biometricauth.KeyStoreUtils.Companion.tryEncrypt
import com.example.android.biometricauth.databinding.ActivityMainBinding
import java.security.*
import javax.crypto.*

class MainActivity : AppCompatActivity(), Callback {

    private lateinit var keyStore: KeyStore
    private lateinit var keyGenerator: KeyGenerator
    private lateinit var sharedPreferences: SharedPreferences
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var binding: ActivityMainBinding

    companion object {
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val DIALOG_FRAGMENT_TAG = "myFragment"
        private const val KEY_NAME_NOT_INVALIDATED = "key_not_invalidated"
        private const val SECRET_MESSAGE = "Very secret message"
        private const val TAG = "MainActivity"
        const val DEFAULT_KEY_NAME = "default_key"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupKeyStoreAndKeyGenerator(ANDROID_KEY_STORE, { keyStore = it }, { keyGenerator = it })
        setupBiometricPrompt()
    }

    private fun setupBiometricPrompt() {
        val (defaultCipher: Cipher, cipherNotInvalidated: Cipher) = setupCiphers()
        sharedPreferences = PreferenceManager.getDefaultSharedPreferences(this)
        biometricPrompt = createBiometricPrompt(this,
                onAuthenticationError = { errorCode, errString ->
                    Log.d(TAG, "$errorCode :: $errString")
                    if (errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON)
                        loginWithPassword() // Because negative button says use application password
                }, onAuthenticationSucceeded = {
                    Log.d(TAG, "Authentication was successful")
                    onPurchased(true, it.cryptoObject)
                }
        )
        setUpPurchaseButtons(cipherNotInvalidated, defaultCipher)
    }

    /**
     * Enables or disables purchase buttons and sets the appropriate click listeners.
     *
     * @param cipherNotInvalidated cipher for the not invalidated purchase button
     * @param defaultCipher the default cipher, used for the purchase button
     */
    private fun setUpPurchaseButtons(cipherNotInvalidated: Cipher, defaultCipher: Cipher) {
        if (BiometricManager.from(application)
                        .canAuthenticate(
                                BiometricManager.Authenticators.BIOMETRIC_STRONG) == BIOMETRIC_SUCCESS
        ) {
            createKey(DEFAULT_KEY_NAME)
            createKey(KEY_NAME_NOT_INVALIDATED, false)

            binding.purchaseButtonNotInvalidated.apply {
                isEnabled = true
                setOnClickListener {
                    purchaseButtonClickListener(cipherNotInvalidated, KEY_NAME_NOT_INVALIDATED)
                }
            }
            binding.purchaseButton.apply {
                isEnabled = true
                setOnClickListener { purchaseButtonClickListener(defaultCipher, DEFAULT_KEY_NAME) }
            }
        } else {
            Toast.makeText(this, getString(R.string.setup_lock_screen), Toast.LENGTH_LONG).show()
            binding.purchaseButton.isEnabled = false
            binding.purchaseButtonNotInvalidated.isEnabled = false
        }
    }

    private fun loginWithPassword() {
        FingerprintAuthenticationDialogFragment().apply {
            setCallback(this@MainActivity)
            show(supportFragmentManager, DIALOG_FRAGMENT_TAG)
        }
    }

    private fun purchaseButtonClickListener(cipher: Cipher, keyName: String) {
        binding.confirmationMessage.visibility = View.GONE
        binding.encryptedMessage.visibility = View.GONE

        if (initCipher(keyStore, cipher, keyName)) {
            biometricPrompt.authenticate(createPromptInfo(this), BiometricPrompt.CryptoObject(cipher))
        } else {
            loginWithPassword()
        }
    }

    // Show confirmation message. Also show crypto information if fingerprint was used.
    private fun showConfirmation(encrypted: ByteArray? = null) {
        binding.confirmationMessage.visibility = View.VISIBLE
        if (encrypted != null) {
            binding.encryptedMessage.apply {
                visibility = View.VISIBLE
                text = Base64.encodeToString(encrypted, 0)
            }
        }
    }

    override fun onPurchased(withBiometrics: Boolean, crypto: BiometricPrompt.CryptoObject?) {
        if (withBiometrics) {
            // If the user authenticated with fingerprint, verify using cryptography and then show
            // the confirmation message.
            crypto?.cipher?.let {
                tryEncrypt(it, { cipher ->
                    showConfirmation(cipher.doFinal(SECRET_MESSAGE.toByteArray()))
                }, { exception ->
                    Toast.makeText(this, "Failed to encrypt the data with the generated key. "
                            + "Retry the purchase", Toast.LENGTH_LONG).show()
                    Log.e(TAG, "Failed to encrypt the data with the generated key. ${exception.message}")
                })
            }
        } else {
            showConfirmation()
        }
    }

    /**
     * Creates a symmetric key in the Android Key Store which can only be used after the user has
     * authenticated with a fingerprint.
     *
     * @param keyName the name of the key to be created
     * @param invalidatedByBiometricEnrollment if `false` is passed, the created key will not be
     * invalidated even if a new fingerprint is enrolled. The default value is `true` - the key will
     * be invalidated if a new fingerprint is enrolled.
     */
    override fun createKey(keyName: String, invalidatedByBiometricEnrollment: Boolean) {
        KeyStoreUtils.createKey(keyStore, keyGenerator, keyName, invalidatedByBiometricEnrollment)
    }
}
