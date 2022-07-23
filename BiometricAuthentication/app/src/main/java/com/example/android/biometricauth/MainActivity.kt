/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package com.example.android.biometricauth

import android.content.Intent
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProperties.BLOCK_MODE_CBC
import android.security.keystore.KeyProperties.ENCRYPTION_PADDING_PKCS7
import android.security.keystore.KeyProperties.KEY_ALGORITHM_AES
import android.util.Base64
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.lifecycle.Observer
import java.io.IOException
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.UnrecoverableKeyException
import java.security.cert.CertificateException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey

/**
 * Main entry point for the sample, showing a backpack and "Purchase" button.
 */
class MainActivity : AppCompatActivity(){

    lateinit var fingerprintRepo: FingerprintRepo

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        fingerprintRepo = FingerprintRepo(this,this, ::loginWithPassword)

        setContentView(R.layout.activity_main)
        setSupportActionBar(findViewById(R.id.toolbar))

        val purchaseButton = findViewById<Button>(R.id.purchase_button)
        val purchaseButtonNotInvalidated =
                findViewById<Button>(R.id.purchase_button_not_invalidated)

        if (fingerprintRepo.IsHaveFingerprint) {

            purchaseButton.setOnClickListener {
                findViewById<View>(R.id.confirmation_message).visibility = View.GONE
                findViewById<View>(R.id.encrypted_message).visibility = View.GONE

                fingerprintRepo.Login()
            }
        } else {
            showToast(getString(R.string.setup_lock_screen))
            purchaseButton.isEnabled = false
            purchaseButtonNotInvalidated.isEnabled = false
        }

        fingerprintRepo.AuthenticationCallback.observe(this, Observer { callback  ->
            if(callback == FingerprintAuthenticationCallback.SUCCESSFUL_RECOGNIZE){
                showConfirmation(fingerprintRepo.EncriptData)
            }
            if(callback == FingerprintAuthenticationCallback.ERROR_RECOGNIZE||
                callback == FingerprintAuthenticationCallback.FAILED_RECOGNIZE){
                loginWithPassword()
            }
        })

    }


    // Show confirmation message. Also show crypto information if fingerprint was used.
    private fun showConfirmation(encrypted: ByteArray? = null) {
        findViewById<View>(R.id.confirmation_message).visibility = View.VISIBLE
        if (encrypted != null) {
            findViewById<TextView>(R.id.encrypted_message).run {
                visibility = View.VISIBLE
                text = Base64.encodeToString(encrypted, 0 /* flags */)
            }
        }
    }


    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == R.id.action_settings) {
            val intent = Intent(this, SettingsActivity::class.java)
            startActivity(intent)
            return true
        }
        return super.onOptionsItemSelected(item)
    }


    private fun loginWithPassword() {
        Log.d(TAG, "Use app password")
        val fragment = FingerprintAuthenticationDialogFragment()
        fragment.setCallback(fingerprintRepo)
        fragment.show(fragmentManager, DIALOG_FRAGMENT_TAG)
    }

    companion object {
        private const val TAG = "MainActivity"
        private const val DIALOG_FRAGMENT_TAG = "myFragment"
    }

}
