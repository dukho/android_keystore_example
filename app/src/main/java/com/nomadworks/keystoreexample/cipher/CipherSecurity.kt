package com.nomadworks.keystoreexample.cipher

import android.annotation.TargetApi
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import java.io.IOException
import java.security.*
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.*
import javax.crypto.spec.GCMParameterSpec

class CipherSecurity {
    companion object {
        val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val TRANSFORMATION_ALGORITHM = "AES/GCM/NoPadding"
        private val FIXED_IV = //initialisation vector
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
                    getKeyParameterSpec(alias)
                )
            } else {
                //TODO this is not complete - for lower Android version (lower than API 23)
                keyGenerator = KeyGenerator.getInstance("AES")
                keyGenerator.init(256, SecureRandom())
            }

            keyGenerator.generateKey()
        }
    }

    @RequiresApi(23)
    private fun getKeyParameterSpec(alias: String): AlgorithmParameterSpec {
        return KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(false)
            .build()
    }

    private fun getCipherParameterSpec(): AlgorithmParameterSpec {
        return GCMParameterSpec(128, FIXED_IV) // authentication tag length can be one of 128, 120, 112, 104, 96
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
        val cipher = Cipher.getInstance(TRANSFORMATION_ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, key, getCipherParameterSpec())
        return cipher.doFinal(textToEncrypt.toByteArray(Charsets.UTF_8))
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
        val cipher = Cipher.getInstance(TRANSFORMATION_ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, key, getCipherParameterSpec())
        return String(cipher.doFinal(encryptedData), Charsets.UTF_8)
    }

}