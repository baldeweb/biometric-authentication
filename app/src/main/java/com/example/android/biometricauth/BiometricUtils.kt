package com.example.android.biometricauth

import android.content.Context
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat

class BiometricUtils {
    companion object {
        fun createPromptInfo(context: Context): BiometricPrompt.PromptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle(context.getString(R.string.prompt_info_title))
                .setSubtitle(context.getString(R.string.prompt_info_subtitle))
                .setDescription(context.getString(R.string.prompt_info_description))
                .setConfirmationRequired(false)
                .setNegativeButtonText(context.getString(R.string.prompt_info_use_app_password))
                // .setDeviceCredentialAllowed(true) // Allow PIN/pattern/password authentication.
                // Also note that setDeviceCredentialAllowed and setNegativeButtonText are
                // incompatible so that if you uncomment one you must comment out the other
                .build()

        fun createBiometricPrompt(
                activity: AppCompatActivity,
                onAuthenticationError: (errorCode: Int, errString: CharSequence) -> Unit,
                onAuthenticationFailed: () -> Unit,
                onAuthenticationSucceeded: (result: BiometricPrompt.AuthenticationResult) -> Unit
        ): BiometricPrompt {
            return BiometricPrompt(
                    activity,
                    ContextCompat.getMainExecutor(activity),
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            super.onAuthenticationError(errorCode, errString)
                            onAuthenticationError.invoke(errorCode, errString)
                        }

                        override fun onAuthenticationFailed() {
                            super.onAuthenticationFailed()
                            onAuthenticationFailed.invoke()
                        }

                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            super.onAuthenticationSucceeded(result)
                            onAuthenticationSucceeded.invoke(result)
                        }
                    }
            )
        }
    }
}