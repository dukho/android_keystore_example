package com.nomadworks.keystoreexample

import android.content.Context
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import com.nomadworks.keystoreexample.cipher.CipherSecurity
import kotlinx.android.synthetic.main.activity_main.*
import java.io.*

class MainActivity : AppCompatActivity() {

    companion object {
        const val ALIAS = "my_secret"   // alias for keystore & file name to save things
    }
    val secure = CipherSecurity()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        initUI()
    }

    fun initUI() {
        btnStore.setOnClickListener {
            val content = editInput.text.toString()
            saveContent(content, ALIAS)
        }

        btnRestore.setOnClickListener {
            val content = readEncryptedContent(ALIAS)
            if (content == null) {
                textRestored.text = "ERROR"
            } else {
                textRestored.text = content
            }
        }
    }

    @Throws(FileNotFoundException::class)
    private fun saveContent(content: String, alias: String):Boolean {
        return try {
            secure.generateSecretKey(alias)
            val fileOutputStream = openFileOutput(alias, Context.MODE_PRIVATE)
            fileOutputStream.write(secure.encrypt(content, alias))
            fileOutputStream.close()
            true
        } catch (e: IOException) {
            if (BuildConfig.DEBUG) {
                e.printStackTrace()
            }
            false
        }
    }

    private fun readEncryptedContent(alias: String): String? {
        try {
            secure.generateSecretKey(alias)
            val file = File(filesDir, alias)
            if (file.exists()) {
                val secure = CipherSecurity()

                val size = file.length().toInt()
                val bytes = ByteArray(size)
                try {
                    val buf = BufferedInputStream(FileInputStream(file))
                    buf.read(bytes, 0, bytes.size)
                    buf.close()

                    val content = secure.decrypt(bytes, alias)
                    return content
                } catch (e: Exception) {
                    e.printStackTrace()
                    return null
                }
            }
        } catch (e: Exception) {
            if (BuildConfig.DEBUG) {
                e.printStackTrace()
            }
        }
        return null
    }
}
