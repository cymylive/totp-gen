package com.cymylive.totpgen

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * 用 Android Keystore 中的 AES-256-GCM 密钥加密整个账号列表，
 * 密文 + IV 存在 SharedPreferences。密钥不出 Keystore。
 */
class SecureStore(private val ctx: Context) {

    companion object {
        private const val PREF = "totpgen_vault"
        private const val KEY_PAYLOAD = "payload"
        private const val KEY_ALIAS = "totpgen_master_key"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val GCM_TAG_BITS = 128
        private const val IV_LEN = 12
    }

    private val prefs = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    private fun getOrCreateKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (ks.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }

        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        kg.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return kg.generateKey()
    }

    fun load(): List<Account> {
        val b64 = prefs.getString(KEY_PAYLOAD, null) ?: return emptyList()
        return try {
            val blob = Base64.decode(b64, Base64.NO_WRAP)
            if (blob.size <= IV_LEN) return emptyList()
            val iv = blob.copyOfRange(0, IV_LEN)
            val cipherText = blob.copyOfRange(IV_LEN, blob.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
            val plain = cipher.doFinal(cipherText).toString(Charsets.UTF_8)
            val arr = JSONArray(plain)
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                Account(
                    name = o.getString("name"),
                    secret = o.getString("secret"),
                    digits = o.optInt("digits", 6),
                    period = o.optInt("period", 30)
                )
            }
        } catch (e: Exception) {
            emptyList()
        }
    }

    fun save(accounts: List<Account>) {
        if (accounts.isEmpty()) {
            prefs.edit().remove(KEY_PAYLOAD).apply()
            return
        }
        val arr = JSONArray()
        accounts.forEach { a ->
            arr.put(
                JSONObject()
                    .put("name", a.name)
                    .put("secret", a.secret)
                    .put("digits", a.digits)
                    .put("period", a.period)
            )
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val iv = cipher.iv
        val encrypted = cipher.doFinal(arr.toString().toByteArray(Charsets.UTF_8))
        val blob = iv + encrypted
        prefs.edit().putString(KEY_PAYLOAD, Base64.encodeToString(blob, Base64.NO_WRAP)).apply()
    }
}
