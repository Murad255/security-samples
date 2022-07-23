package com.biometric.fingerprint

import androidx.biometric.BiometricPrompt

interface IFingerprintCallback {
    fun onPurchased(withBiometrics: Boolean, crypto: BiometricPrompt.CryptoObject? = null)
    fun createKey(keyName: String, invalidatedByBiometricEnrollment: Boolean = true)
}
