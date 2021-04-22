package com.example.android.biometricauth

import androidx.biometric.BiometricPrompt
import java.security.KeyStore

interface Callback {
    fun onPurchased(withBiometrics: Boolean, crypto: BiometricPrompt.CryptoObject? = null)
    fun createKey(keyName: String, invalidatedByBiometricEnrollment: Boolean = true)
}