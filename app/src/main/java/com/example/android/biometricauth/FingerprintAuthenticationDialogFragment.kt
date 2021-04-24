package com.example.android.biometricauth

import android.content.Context
import android.content.SharedPreferences
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import androidx.fragment.app.DialogFragment
import androidx.preference.PreferenceManager
import com.example.android.biometricauth.MainActivity.Companion.DEFAULT_KEY_NAME
import com.example.android.biometricauth.databinding.FingerprintDialogContainerBinding

class FingerprintAuthenticationDialogFragment : DialogFragment() {

    private lateinit var callback: Callback
    private lateinit var sharedPreferences: SharedPreferences
    private lateinit var binding: FingerprintDialogContainerBinding

    override fun onCreateView(inflater: LayoutInflater,
                              container: ViewGroup?,
                              savedInstanceState: Bundle?
    ): View {
        sharedPreferences = PreferenceManager.getDefaultSharedPreferences(context)
        setStyle(STYLE_NORMAL, android.R.style.Theme_Material_Light_Dialog)
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
                verifyPassword()
                true
            } else {
                false
            }
        }
        binding.secondDialogButton.setOnClickListener { verifyPassword() }
    }

    fun setCallback(callback: Callback) {
        this.callback = callback
    }

    private fun verifyPassword() {
        if (binding.password.text.toString().isEmpty()) return

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

}
