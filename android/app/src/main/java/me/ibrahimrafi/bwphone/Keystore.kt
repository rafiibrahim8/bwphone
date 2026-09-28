package me.ibrahimrafi.bwphone

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.InvalidAlgorithmParameterException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/**
 * One RSA-2048 unwrap key per account, in the TEE (StrongBox where it
 * works), fingerprint-gated on every use, destroyed by any new fingerprint
 * enrolment. The `Cipher` it initialises is the `CryptoObject` the prompt
 * binds to, so one fingerprint authorises exactly one decrypt.
 */
object Keystore {
    private const val PREFIX = "bwphone-unwrap-v1-"

    /** The account's Keystore key is gone: screen lock removed, or never created. */
    class KeyMissing(alias: String) : Exception("no key $alias")

    /** The phone made the key in software: nothing would stop root from copying it. */
    class NotInSecureHardware : Exception("this phone can't keep the key in secure hardware")

    fun alias(accountHex: String) = PREFIX + accountHex

    private fun store() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun hasKey(accountHex: String): Boolean = store().containsAlias(alias(accountHex))

    fun delete(accountHex: String) {
        val ks = store()
        if (ks.containsAlias(alias(accountHex))) ks.deleteEntry(alias(accountHex))
    }

    /** The public half, X.509 SPKI DER: what the PC wraps to. */
    fun publicKeyDer(accountHex: String): ByteArray =
        store().getCertificate(alias(accountHex))?.publicKey?.encoded ?: throw KeyMissing(alias(accountHex))

    /**
     * Exactly the spec's flags. StrongBox first; some devices throw
     * `ProviderException` rather than `StrongBoxUnavailableException`, so both
     * fall back to the ordinary TEE. A key that ends up outside secure
     * hardware is deleted and refused: from Android 9 up that should never
     * happen, and the vault must not rest on a key root could copy.
     */
    @Throws(NotInSecureHardware::class)
    fun generate(accountHex: String): ByteArray {
        fun spec(strongBox: Boolean): KeyGenParameterSpec {
            val b = KeyGenParameterSpec.Builder(alias(accountHex), KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(2048)
                // OAEP's label hash is SHA-256. SHA-1 is listed because it is the MGF1
                // digest, and some KeyMint versions check MGF1 against the declared set.
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
            if (Build.VERSION.SDK_INT >= 30) {
                // 0 = every single use, bound to the CryptoObject's operation; biometric only.
                b.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            } else {
                // The same before Android 11: -1 = auth for every use, through a CryptoObject,
                // which only a biometric can give (the device PIN cannot authorise per-use keys).
                @Suppress("DEPRECATION")
                b.setUserAuthenticationValidityDurationSeconds(-1)
            }
            if (strongBox) b.setIsStrongBoxBacked(true)
            return b.build()
        }

        val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
        val pair = try {
            gen.initialize(spec(true))
            gen.generateKeyPair()
        } catch (e: StrongBoxUnavailableException) {
            gen.initialize(spec(false))
            gen.generateKeyPair()
        } catch (e: ProviderException) {
            gen.initialize(spec(false))
            gen.generateKeyPair()
        }
        if (!inSecureHardware(pair.private)) {
            delete(accountHex)
            throw NotInSecureHardware()
        }
        return pair.public.encoded
    }

    private fun inSecureHardware(key: PrivateKey): Boolean {
        val info = KeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java)
        return if (Build.VERSION.SDK_INT >= 31) {
            info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
        } else {
            @Suppress("DEPRECATION")
            info.isInsideSecureHardware
        }
    }

    /**
     * A decrypt cipher for the account, parameters stated explicitly: SHA-256
     * label hash, MGF1-SHA1, as the PC wraps (vault.blob 0x04). Keystore
     * before Android 14 refuses any other MGF1 digest; naming it here keeps the
     * two ends agreeing whatever `"OAEPwith…"` string defaults would pick.
     *
     * Throws [KeyPermanentlyInvalidatedException] (new fingerprint enrolled)
     * or [KeyMissing] (key deleted); both mean re-enrolment.
     */
    @Throws(KeyPermanentlyInvalidatedException::class, KeyMissing::class)
    fun decryptCipher(accountHex: String): Cipher {
        val key = try {
            store().getKey(alias(accountHex), null) as? PrivateKey
        } catch (e: Exception) {
            null
        } ?: throw KeyMissing(alias(accountHex))
        val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            key,
            OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT),
        )
        return cipher
    }

    /**
     * True if the key is usable; records nothing. Run at service start and
     * after restarts. A key this phone refuses to use with our parameters
     * counts as unusable too, so it shows as "enrol again" instead of a crash.
     */
    fun probe(accountHex: String): Boolean = try {
        decryptCipher(accountHex)
        true
    } catch (e: KeyPermanentlyInvalidatedException) {
        false
    } catch (e: KeyMissing) {
        false
    } catch (e: InvalidAlgorithmParameterException) {
        false
    }
}
