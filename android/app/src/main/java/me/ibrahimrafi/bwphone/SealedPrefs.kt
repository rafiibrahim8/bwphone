package me.ibrahimrafi.bwphone

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * SharedPreferences with every value sealed under an AES-256-GCM key that
 * lives in AndroidKeyStore and never leaves it. This replaces
 * `androidx.security:security-crypto`, which Google deprecated in favour of
 * exactly this: the platform APIs and the Keystore directly.
 *
 * On disk, each value is `base64(iv(12) || ciphertext || tag)`; the
 * preference's name is the GCM associated data, so a value moved from one
 * key to another by editing the file fails to open. Names stay plaintext —
 * nothing in them is secret (account ids are random). Ints, longs and string
 * sets are serialised to strings before sealing.
 *
 * The key needs no user authentication: it protects the file at rest, not
 * an operation, and the service must read it with the phone locked. A
 * storage dump without the TEE yields ciphertext.
 */
class SealedPrefs(context: Context, name: String) {
    private val prefs = context.getSharedPreferences(name, Context.MODE_PRIVATE)
    private val key: SecretKey = loadOrCreateKey()

    fun contains(k: String) = prefs.contains(k)
    fun keys(): Set<String> = prefs.all.keys

    fun getString(k: String, default: String?): String? = open(k)?.let { String(it, Charsets.UTF_8) } ?: default
    fun getInt(k: String, default: Int): Int = getString(k, null)?.toIntOrNull() ?: default
    fun getLong(k: String, default: Long): Long = getString(k, null)?.toLongOrNull() ?: default
    fun getStringSet(k: String, default: Set<String>): Set<String> =
        getString(k, null)?.let { s -> if (s.isEmpty()) emptySet() else s.split('\u0000').toSet() } ?: default

    fun edit() = Editor()

    inner class Editor {
        private val e = prefs.edit()

        fun putString(k: String, v: String?) = apply { if (v == null) e.remove(k) else e.putString(k, seal(k, v.toByteArray(Charsets.UTF_8))) }
        fun putInt(k: String, v: Int) = putString(k, v.toString())
        fun putLong(k: String, v: Long) = putString(k, v.toString())
        fun putStringSet(k: String, v: Set<String>) = putString(k, v.joinToString("\u0000"))
        fun remove(k: String) = apply { e.remove(k) }
        fun clear() = apply { e.clear() }
        fun apply() {
            e.apply()
            AppState.changed()
        }
    }

    private fun seal(name: String, plain: ByteArray): String {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key)   // the Keystore picks a fresh random IV
        c.updateAAD(name.toByteArray(Charsets.UTF_8))
        val iv = c.iv
        val ct = c.doFinal(plain)
        return Base64.encodeToString(iv + ct, Base64.NO_WRAP)
    }

    private fun open(name: String): ByteArray? {
        val stored = prefs.getString(name, null) ?: return null
        return try {
            val blob = Base64.decode(stored, Base64.NO_WRAP)
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, blob, 0, IV_LEN))
            c.updateAAD(name.toByteArray(Charsets.UTF_8))
            c.doFinal(blob, IV_LEN, blob.size - IV_LEN)
        } catch (e: Exception) {
            // Tampered, or sealed under a key that no longer exists: treat as absent.
            null
        }
    }

    private fun loadOrCreateKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return gen.generateKey()
    }

    companion object {
        private const val ALIAS = "bwphone-prefs-v1"
        private const val IV_LEN = 12
    }
}
