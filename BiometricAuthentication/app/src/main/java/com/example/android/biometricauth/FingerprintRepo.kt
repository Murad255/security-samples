package com.example.android.biometricauth

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
import android.preference.PreferenceManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Log
import android.widget.Toast
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.MutableLiveData
import java.io.IOException
import java.security.*
import java.security.cert.CertificateException
import javax.crypto.*

class FingerprintRepo(private val context: Context,
                      private val biometricPromptFragment: FragmentActivity,
                      private val loginWithPassword: ()->Unit)
    : FingerprintAuthenticationDialogFragment.Callback{


    private lateinit var keyStore: KeyStore
    private lateinit var keyGenerator: KeyGenerator
    private lateinit var sharedPreferences: SharedPreferences
    private lateinit var biometricPrompt: BiometricPrompt


    private lateinit var  defaultCipher: Cipher
    private lateinit var  cipherNotInvalidated: Cipher

    private var isHaveFingerprint: Boolean = false

    var IsHaveFingerprint: Boolean = false
        get(){
            return isHaveFingerprint
        }

    private var encriptData: ByteArray?= null
    var EncriptData: ByteArray? = null
        get(){
            return encriptData
        }


    var AuthenticationCallback = MutableLiveData<FingerprintAuthenticationCallback>()

    init {
        AuthenticationCallback.value = FingerprintAuthenticationCallback.NOT_INICIALIZED

        setupKeyStoreAndKeyGenerator()

        setupCiphers()
        sharedPreferences = PreferenceManager.getDefaultSharedPreferences(context)
        biometricPrompt = createBiometricPrompt()

        if (BiometricManager.from(context).canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS)
        {
            createKey(com.example.android.biometricauth.DEFAULT_KEY_NAME)
            createKey(KEY_NAME_NOT_INVALIDATED, false)

            isHaveFingerprint = true
        }
    }

     fun  Login(){
         val promptInfo = createPromptInfo()

         if (initCipher()) {
             biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(defaultCipher))
         } else {
             loginWithPassword()
         }
     }


    /**
     * Sets up KeyStore and KeyGenerator
     */
    private fun setupKeyStoreAndKeyGenerator() {
        try {
            keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
        } catch (e: KeyStoreException) {
            throw RuntimeException("Failed to get an instance of KeyStore", e)
        }

        try {
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
        } catch (e: Exception) {
            when (e) {
                is NoSuchAlgorithmException,
                is NoSuchProviderException ->
                    throw RuntimeException("Failed to get an instance of KeyGenerator", e)
                else -> throw e
            }
        }
    }

    /**
     * Sets up default cipher and a non-invalidated cipher
     */
    private fun setupCiphers(){
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
    }

    /**
     * Initialize the [Cipher] instance with the created key in the [createKey] method.
     *
     * @param keyName the key name to init the cipher
     * @return `true` if initialization succeeded, `false` if the lock screen has been disabled or
     * reset after key generation, or if a fingerprint was enrolled after key generation.
     */
     private fun initCipher(cipher: Cipher = defaultCipher, keyName: String = DEFAULT_KEY_NAME): Boolean {
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
     * Proceed with the purchase operation
     *
     * @param withBiometrics `true` if the purchase was made by using a fingerprint
     * @param crypto the Crypto object
     */
    override  fun onPurchased(withBiometrics: Boolean, crypto: BiometricPrompt.CryptoObject?) {
        if (withBiometrics) {
            // If the user authenticated with fingerprint, verify using cryptography and then show
            // the confirmation message.
            crypto?.cipher?.let { encriptData = tryEncrypt(it) }
        } else {
            // Authentication happened with backup password. Just show the confirmation message.
            Log.d(TAG, "Authentication happened with backup password")

        }
    }


    /**
     * Tries to encrypt some data with the generated key from [createKey]. This only works if the
     * user just authenticated via fingerprint.
     */
    private fun tryEncrypt(cipher: Cipher): ByteArray? {
        try {
            return cipher.doFinal(SECRET_MESSAGE.toByteArray())
        } catch (e: Exception) {
            when (e) {
                is BadPaddingException,
                is IllegalBlockSizeException -> {
                    Toast.makeText(context, "Failed to encrypt the data with the generated key. "
                            + "Retry the purchase", Toast.LENGTH_LONG).show()
                    Log.e(TAG, "Failed to encrypt the data with the generated key. ${e.message}")
                }
                else -> throw e
            }
            return null
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
        // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
        // for your flow. Use of keys is necessary if you need to know if the set of enrolled
        // fingerprints has changed.
        try {
            keyStore.load(null)

            val keyProperties = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            val builder = KeyGenParameterSpec.Builder(keyName, keyProperties)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setUserAuthenticationRequired(true)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment)

            keyGenerator.run {
                init(builder.build())
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


    private fun createBiometricPrompt(): BiometricPrompt {
        val executor = ContextCompat.getMainExecutor(context)

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            @SuppressLint("RestrictedApi")
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                Log.d(TAG, "$errorCode :: $errString")
                AuthenticationCallback.value = FingerprintAuthenticationCallback.ERROR_RECOGNIZE
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                Log.d(TAG, "Authentication failed for an unknown reason")
                AuthenticationCallback.value = FingerprintAuthenticationCallback.FAILED_RECOGNIZE
            }

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                Log.d(TAG, "Authentication was successful")
                AuthenticationCallback.value = FingerprintAuthenticationCallback.SUCCESSFUL_RECOGNIZE
                onPurchased(true, result.cryptoObject)
            }
        }

        val biometricPrompt = BiometricPrompt(biometricPromptFragment, executor, callback)
        return biometricPrompt
    }

     fun createPromptInfo(): BiometricPrompt.PromptInfo {
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(context.getString(R.string.prompt_info_title))
            .setSubtitle(context.getString(R.string.prompt_info_subtitle))
            .setDescription(context.getString(R.string.prompt_info_description))
            .setConfirmationRequired(false)
            .setNegativeButtonText(context.getString(R.string.prompt_info_use_app_password))
            // .setDeviceCredentialAllowed(true) // Allow PIN/pattern/password authentication.
            // Also note that setDeviceCredentialAllowed and setNegativeButtonText are
            // incompatible so that if you uncomment one you must comment out the other
            .build()
        return promptInfo
    }

    companion object {
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val KEY_NAME_NOT_INVALIDATED = "key_not_invalidated"
        private const val SECRET_MESSAGE = "Very secret message"
        private const val TAG = "FingerprintRepo"
    }
}