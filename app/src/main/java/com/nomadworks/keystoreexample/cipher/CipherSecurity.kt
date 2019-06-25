package com.nomadworks.keystoreexample.cipher

import android.annotation.TargetApi
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import com.nomadworks.keystoreexample.BuildConfig
import java.io.IOException
import java.security.*
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.*
import javax.crypto.spec.GCMParameterSpec

class CipherSecurity {
    companion object {
        val ANDROID_KEY_STORE = "AndroidKeyStore"
        private val TRANSFORMATION = "AES/GCM/NoPadding"
        private val FIXED_IV =
            "0123456789ab".toByteArray() //The IV you use in the encryption must be the same one you use in the decryption

    }

    private var keyStore: KeyStore

    init {
        keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
        keyStore.load(null)
    }

    @TargetApi(23)
    @Throws(NoSuchAlgorithmException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class)
    fun generateSecretKey(alias: String) {
        if (!keyStore.containsAlias(alias)) {

            val keyGenerator: KeyGenerator
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                keyGenerator = KeyGenerator
                    .getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
                keyGenerator.init(
                    getParameterSpec(alias)
                )
            } else {
                keyGenerator = KeyGenerator.getInstance("AES")
                keyGenerator.init(256, SecureRandom())
            }

            keyGenerator.generateKey()
        }
    }

    @RequiresApi(23)
    private fun getParameterSpec(alias: String): AlgorithmParameterSpec {
        return KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(false)
            .build()
    }

    @Throws(
        UnrecoverableEntryException::class,
        NoSuchAlgorithmException::class,
        KeyStoreException::class,
        NoSuchProviderException::class,
        NoSuchPaddingException::class,
        InvalidKeyException::class,
        IOException::class,
        InvalidAlgorithmParameterException::class,
        SignatureException::class,
        BadPaddingException::class,
        IllegalBlockSizeException::class
    )
    internal fun encrypt(textToEncrypt: String, alias: String): ByteArray {
        val key = (keyStore.getEntry(alias, null) as KeyStore.SecretKeyEntry).secretKey
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, FIXED_IV))
        return cipher.doFinal(textToEncrypt.toByteArray())
    }

    @Throws(
        UnrecoverableEntryException::class,
        NoSuchAlgorithmException::class,
        KeyStoreException::class,
        NoSuchProviderException::class,
        NoSuchPaddingException::class,
        InvalidKeyException::class,
        IOException::class,
        BadPaddingException::class,
        IllegalBlockSizeException::class,
        InvalidAlgorithmParameterException::class
    )
    internal fun decrypt(encryptedData: ByteArray, alias: String): String {
        val key = (keyStore.getEntry(alias, null) as KeyStore.SecretKeyEntry).secretKey
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val spec = GCMParameterSpec(128, FIXED_IV)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        return String(cipher.doFinal(encryptedData), charset("UTF-8"))
    }

}