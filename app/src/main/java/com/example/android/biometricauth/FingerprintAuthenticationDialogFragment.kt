package com.example.android.biometricauth

import android.content.Context
import android.content.SharedPreferences
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.DialogFragment
import androidx.preference.PreferenceManager
import com.example.android.biometricauth.MainActivity.Companion.DEFAULT_KEY_NAME
import com.example.android.biometricauth.databinding.FingerprintDialogContainerBinding

class FingerprintAuthenticationDialogFragment : DialogFragment() {

    private lateinit var callback: Callback
    private lateinit var sharedPreferences: SharedPreferences
    private lateinit var binding: FingerprintDialogContainerBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        retainInstance = true
        setStyle(STYLE_NORMAL, android.R.style.Theme_Material_Light_Dialog)
    }

    override fun onCreateView(inflater: LayoutInflater,
                              container: ViewGroup?,
                              savedInstanceState: Bundle?
    ): View? {
        dialog?.setTitle(getString(R.string.sign_in))
        binding = FingerprintDialogContainerBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.cancelButton.setText(R.string.cancel)
        binding.cancelButton.setOnClickListener { dismiss() }

        binding.secondDialogButton.setText(R.string.ok)

        binding.password.setOnEditorActionListener { _, actionId, _ ->
            return@setOnEditorActionListener if (actionId == EditorInfo.IME_ACTION_GO) {
                verifyPassword();
                true
            } else {
                false
            }
        }
        binding.secondDialogButton.setOnClickListener { verifyPassword() }
    }

    override fun onAttach(context: Context) {
        super.onAttach(context)
        sharedPreferences = PreferenceManager.getDefaultSharedPreferences(context)
    }

    fun setCallback(callback: Callback) {
        this.callback = callback
    }

    /**
     * Checks whether the current entered password is correct, and dismisses the dialog and
     * informs the activity about the result.
     */
    private fun verifyPassword() {
        if (!checkPassword(binding.password.text.toString())) return

        if (binding.useFingerprintInFutureCheck.isChecked) {
            sharedPreferences.apply {
                edit().putBoolean(
                        getString(R.string.use_fingerprint_to_authenticate_key),
                        binding.useFingerprintInFutureCheck.isChecked
                ).apply()
            }
            // Re-create the key so that fingerprints including new ones are validated.
            callback.createKey(DEFAULT_KEY_NAME)
        }
        binding.password.setText("")
        callback.onPurchased(withBiometrics = false)
        dismiss()
    }

    /**
     * Checks if the given password is valid. Assume that the password is always correct.
     * In a real world situation, the password needs to be verified via the server.
     *
     * @param password The password String
     *
     * @return true if `password` is correct, false otherwise
     */
    private fun checkPassword(password: String) = password.isNotEmpty()

    interface Callback {
        fun onPurchased(withBiometrics: Boolean, crypto: BiometricPrompt.CryptoObject? = null)
        fun createKey(keyName: String, invalidatedByBiometricEnrollment: Boolean = true)
    }
}
