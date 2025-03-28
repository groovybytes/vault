package com.example.vault

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.Uri
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.documentfile.provider.DocumentFile
import androidx.fragment.app.Fragment
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import com.ionspin.kotlin.crypto.LibsodiumInitializer
import com.ionspin.kotlin.crypto.box.Box
import com.ionspin.kotlin.crypto.pwhash.PasswordHash
import com.ionspin.kotlin.crypto.pwhash.crypto_pwhash_argon2id_ALG_ARGON2ID13
import com.ionspin.kotlin.crypto.secretbox.SecretBox
import com.ionspin.kotlin.crypto.secretbox.crypto_secretbox_NONCEBYTES
import com.ionspin.kotlin.crypto.secretstream.SecretStream
import com.ionspin.kotlin.crypto.secretstream.crypto_secretstream_xchacha20poly1305_TAG_FINAL
import com.ionspin.kotlin.crypto.secretstream.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
import com.ionspin.kotlin.crypto.util.LibsodiumRandom
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import kotlinx.coroutines.yield
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.coroutines.cancellation.CancellationException
import kotlin.coroutines.coroutineContext

/**
 * Represents the result of encrypting a key (or vault) that is wrapped.
 */
data class WrappedKeyResult(
  val encryptedKey: ByteArray,    // The wrapped key (e.g. file key or vault key)
  val wrappingNonce: ByteArray    // The nonce used in the wrapping process
)

/**
 * Represents the result of encrypting file data.
 */
data class FileEncryptionResult(
  val encryptedFileData: ByteArray, // The ciphertext of the file content
  val dataNonce: ByteArray, // The nonce used in the wrapping process
  val wrappedFileKey: WrappedKeyResult // The wrapped file key result
)

/**
 * Holds information derived from a credential.
 */
data class CredentialInfo(
  val derivedKEK: ByteArray,
  val encryptedKeyKey: String,
  val ivKey: String,
  val isRecovery: Boolean
)

class SecureKeyVault(private val context: Context, private val activity: Fragment) {

  companion object {
    const val RECOVERY_KEY_PREFIX = "+RECV*"

    private const val ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val VAULT_KEYSTORE_ALIAS = "VaultKeyStoreAlias"
    private const val VAULT_PREFS_ACCESS_KEY = "VaultSharedPrefs"

    private const val PASSWORD_HASH_SALT_ACCESS_KEY = "PasswordHashSalt"

    private const val ENCRYPTED_MASTER_KEY_BIO_ACCESS_KEY = "EncryptedMasterKeyBIO"
    private const val INITIALIZATION_VECTOR_BIO_ACCESS_KEY = "InitializationVectorBIO"

    private const val ENCRYPTED_MASTER_KEY_PW_ACCESS_KEY = "EncryptedMasterKeyPW"
    private const val INITIALIZATION_VECTOR_PW_ACCESS_KEY = "InitializationVectorPW"

    private const val ENCRYPTED_MASTER_KEY_RK_ACCESS_KEY = "EncryptedMasterKeyRK"
    private const val INITIALIZATION_VECTOR_RK_ACCESS_KEY = "InitializationVectorRK"

    private val MASTER_KEY_ALIAS = MasterKeys.AES256_GCM_SPEC

    private const val ENCRYPTION_BLOCK_MODE = KeyProperties.BLOCK_MODE_GCM
    private const val ENCRYPTION_PADDING = KeyProperties.ENCRYPTION_PADDING_NONE
    private const val ENCRYPTION_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
    private const val ENCRYPTION_KEY_SIZE = 256

    // Argon2id parameters
    private const val ARGON2_SALT_LENGTH = 16
    private const val ARGON2_TIME_COST = 3

    private const val ARGON2_MEMORY_COST = 8 * 1024 * 1024
    private const val ARGON2_OUTPUT_LENGTH = 32

    // Create EncryptedSharedPreferences instance
    private fun getEncryptedPrefs(context: Context): SharedPreferences {
      val masterKeyAlias = MasterKeys.getOrCreate(MASTER_KEY_ALIAS)
      return EncryptedSharedPreferences.create(
        VAULT_PREFS_ACCESS_KEY,
        masterKeyAlias,
        context,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
      )
    }

    /**
     * Derives a 32-byte key from the given password (or recovery key) using Argon2id.
     * The salt is securely stored in EncryptedSharedPreferences.
     *
     * @param password The user password (optional if recoveryKey is provided).
     * @param recoveryKey The recovery key (optional if password is provided).
     * @param context The Android context used for accessing secure storage.
     *
     * @return The derived key as a UByteArray.
     */
    @OptIn(ExperimentalUnsignedTypes::class)
    fun deriveKeyFromPassword(
      password: String? = null,
      recoveryKey: String? = null,
      context: Context
    ): UByteArray {
      require(password != null || recoveryKey != null) {
        "Either a password or a recovery key must be provided"
      }

      val encryptedPrefs = getEncryptedPrefs(context)
      val saltBase64 = encryptedPrefs.getString(PASSWORD_HASH_SALT_ACCESS_KEY, null)

      val salt: UByteArray = if (saltBase64 != null) {
        Base64.decode(saltBase64, Base64.DEFAULT).toUByteArray()
      } else {
        val newSalt = LibsodiumRandom.buf(ARGON2_SALT_LENGTH)
        val newSaltBase64 = Base64.encodeToString(newSalt.toByteArray(), Base64.DEFAULT)
        encryptedPrefs.edit { putString(PASSWORD_HASH_SALT_ACCESS_KEY, newSaltBase64) }
        newSalt.toUByteArray()
      }

      val keyInput: String = recoveryKey?.removePrefix("$RECOVERY_KEY_PREFIX-") ?: password!!
      return PasswordHash.pwhash(
        outputLength = ARGON2_OUTPUT_LENGTH,
        password = keyInput, // or recovery key if applicable
        salt = salt,
        opsLimit = ARGON2_TIME_COST.toULong(),  // mapping our time cost
        memLimit = ARGON2_MEMORY_COST,          // our memory cost in bytes
        algorithm = crypto_pwhash_argon2id_ALG_ARGON2ID13  // constant from libsodium for Argon2id
      )
    }

    /**
     * Resolves the KEK and storage keys based on the provided credential.
     */
    @OptIn(ExperimentalUnsignedTypes::class)
    private fun resolveCredentialInfo(credential: String, context: Context): CredentialInfo {
      val isRecovery = credential.startsWith("$RECOVERY_KEY_PREFIX-")
      val derivedKEK = deriveKeyFromPassword(
        if (isRecovery) null else credential,
        if (isRecovery) credential else null,
        context
      ).toByteArray()

      val (encryptedKeyKey, ivKey) = if (isRecovery) {
        Pair(ENCRYPTED_MASTER_KEY_RK_ACCESS_KEY, INITIALIZATION_VECTOR_RK_ACCESS_KEY)
      } else {
        Pair(ENCRYPTED_MASTER_KEY_PW_ACCESS_KEY, INITIALIZATION_VECTOR_PW_ACCESS_KEY)
      }
      return CredentialInfo(derivedKEK, encryptedKeyKey, ivKey, isRecovery)
    }
  }

  // Initialize Libsodium
  fun init(callback: () -> Unit) {
    if (!LibsodiumInitializer.isInitialized()) {
      LibsodiumInitializer.initializeWithCallback(callback)
    } else {
      callback()
    }
  }

  // Check if the device supports biometrics or device credentials
  private fun canAuthenticate(): Boolean {
    val biometricManager = BiometricManager.from(context)
    val canAuthenticate = biometricManager.canAuthenticate(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
    return canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS
  }

  /**
   * Supports both biometric and KEK-based (password or recovery key) flows.
   *
   * @param masterKey Optional master key (if provided externally).
   * @param credential Optional credential string. If provided, the KEK-based flow is used.
   *                   It can be a password or a recovery key (indicated by the RECOVERY_KEY_PREFIX).
   * @param onSuccess Callback with the decrypted (or newly generated) master key and an optional recovery key.
   * @param onFailure Callback with an error message.
   */
  @OptIn(ExperimentalUnsignedTypes::class)
  fun authenticate(
    credential: String?,
    onSuccess: (ByteArray, recoveryKey: String?) -> Unit,
    onFailure: (String) -> Unit
  ) {
    try {
      println("Starting authenticate. Credential provided: ${credential != null}")

      val encryptedPrefs = getEncryptedPrefs(context)
      if (credential != null) {
        // Use the KEK-based flow.
        authenticateMasterKeyUsingCredentials(credential, onSuccess, onFailure)
      } else {
        // Biometric flow (unchanged)
        println("No credential provided; falling back to biometric authentication.")

        if (!canAuthenticate()) {
          onFailure("Device does not support biometrics or device credentials")
          return
        }

        val encryptedMasterKeyBase64 = encryptedPrefs.getString(ENCRYPTED_MASTER_KEY_BIO_ACCESS_KEY, null)
        val masterKeyInitializationVectorBase64 = encryptedPrefs.getString(INITIALIZATION_VECTOR_BIO_ACCESS_KEY, null)

        if (encryptedMasterKeyBase64 != null && masterKeyInitializationVectorBase64 != null) {
          accessMasterKeyUsingBiometrics(
            Base64.decode(encryptedMasterKeyBase64, Base64.DEFAULT),
            Base64.decode(masterKeyInitializationVectorBase64, Base64.DEFAULT),
            onSuccess,
            onFailure
          )
        } else {
          // Encrypt and store the master key using the Keystore and biometric prompt.
          generateMasterKeyUsingBiometrics(encryptedPrefs, onSuccess, onFailure)
        }
      }
    } catch (e: Exception) {
      println("Authentication failed: ${e.message}")
      onFailure("Failed to authenticate: ${e.message}")
    }
  }

  /**
   * Generates a new master key or Accesses an existing master key using the provided credential (password or recovery key).
   * Derives the Key Encryption Key (KEK) from the credential and uses it to unwrap (decrypt) the master key.
   *
   * During generation the master key is wrapped (encrypted) using a KEK derived from the credential and stored.
   */
  @OptIn(ExperimentalUnsignedTypes::class)
  fun authenticateMasterKeyUsingCredentials(
    credential: String,
    onSuccess: (ByteArray, recoveryKey: String?) -> Unit,
    onFailure: (String) -> Unit
  ) {
    try {
      // Resolve credential info to get the derived KEK and storage keys.
      val info = resolveCredentialInfo(credential, context)

      // Retrieve the stored wrapped master key.
      val encryptedPrefs = getEncryptedPrefs(context)
      val encryptedMasterKeyBase64 = encryptedPrefs.getString(info.encryptedKeyKey, null)
      val masterKeyIVBase64 = encryptedPrefs.getString(info.ivKey, null)

      if (encryptedMasterKeyBase64 != null && masterKeyIVBase64 != null) {
        println("Accessing master key using credentials. Recovery mode: ${info.isRecovery}")

        // Decode the stored wrapped master key and its IV.
        val encryptedMasterKeyBytes = Base64.decode(encryptedMasterKeyBase64, Base64.DEFAULT)
        val ivBytes = Base64.decode(masterKeyIVBase64, Base64.DEFAULT)
        val wrappedKeyResult = WrappedKeyResult(encryptedMasterKeyBytes, ivBytes)

        // Unwrap (decrypt) the master key using the derived KEK.
        val unwrappedMasterKey = unwrapEncryptionKey(wrappedKeyResult, info.derivedKEK)

        println("Master key successfully unwrapped using credentials.")
        onSuccess(unwrappedMasterKey, null)
      } else {
        println("Generating master key using credentials. Recovery mode: ${info.isRecovery}")

        // Generate a new 32-byte master key if one isn’t provided.
        val newMasterKey = LibsodiumRandom.buf(32).toByteArray()
        require(newMasterKey.size == 32) { "Master key must be 32 bytes" }

        // Generate a recovery key (this may be null for password-based flows if desired).
        val recoveryKey = generateRecoveryKey()

        // Wrap the master key using the derived KEK.
        val wrappedKeyResult = wrapEncryptionKey(newMasterKey, info.derivedKEK)
        val encryptedKeyBase64 = Base64.encodeToString(wrappedKeyResult.encryptedKey, Base64.DEFAULT)
        val ivBase64 = Base64.encodeToString(wrappedKeyResult.wrappingNonce, Base64.DEFAULT)

        // Persist the wrapped key and IV under the appropriate keys.
        encryptedPrefs.edit {
          putString(info.encryptedKeyKey, encryptedKeyBase64)
          putString(info.ivKey, ivBase64)
        }

        println("New master key generated and stored using credentials.")
        onSuccess(newMasterKey, recoveryKey)
      }
    } catch (e: Exception) {
      onFailure("Failed to access and/or generate master key using credentials: ${e.message}")
    }
  }

  /**
   * Generates a new master key using biometric authentication (fingerprint, face unlock, lockscreen pin, etc...).
   * Derives the Key Encryption Key (KEK) using biometric ciphers and uses it to wrap (encrypt) the master key and store it.
   */
  @OptIn(ExperimentalUnsignedTypes::class)
  private fun generateMasterKeyUsingBiometrics(
    encryptedPrefs: SharedPreferences,
    onSuccess: (ByteArray, recoveryKey: String?) -> Unit,
    onFailure: (String) -> Unit
  ) {
    val executor = ContextCompat.getMainExecutor(context)
    val biometricPrompt = BiometricPrompt(activity, executor, object : BiometricPrompt.AuthenticationCallback() {
      override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
        super.onAuthenticationSucceeded(result)
        try {
          val cipher = result.cryptoObject?.cipher
            ?: throw IllegalStateException("Biometric CryptoObject Cipher is null for generating the master key")

          // Generate a 32-byte master key using LibSodium or use the provided masterKey
          val masterKey = LibsodiumRandom.buf(32).toByteArray()
          require(masterKey.size == 32) { "Master key must be 32 bytes" }

          // Generate a recovery key for the master unlock process.
          val recoveryKey = generateRecoveryKey()

          // Encrypt the master key using the Keystore cipher
          val encryptedMasterKey = cipher.doFinal(masterKey)
          val iv = cipher.iv

          val encryptedMasterKeyBase64 = Base64.encodeToString(encryptedMasterKey, Base64.DEFAULT)
          val ivBase64 = Base64.encodeToString(iv, Base64.DEFAULT)

          // Store the encrypted master key
          encryptedPrefs.edit {
            putString(ENCRYPTED_MASTER_KEY_BIO_ACCESS_KEY, encryptedMasterKeyBase64)
            putString(INITIALIZATION_VECTOR_BIO_ACCESS_KEY, ivBase64)
          }

          // Return the master key and the generated recovery key
          onSuccess(masterKey, recoveryKey)
        } catch (e: Exception) {
          onFailure("Failed to generate and store master key for biometric authentication: ${e.message}")
        }
      }

      override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
        onFailure("Biometric Authentication error: $errString")
      }

      override fun onAuthenticationFailed() {
        onFailure("Biometric Authentication failed")
      }
    })

    // Get a cipher for encryption
    val cipher = getCipher()
    cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKeystoreKey())

    // Attach the CryptoObject to the BiometricPrompt
    val cryptoObject = BiometricPrompt.CryptoObject(cipher)

    // Lets the user authenticate using either a Class 3 biometric or
    // their lock screen credential (PIN, pattern, or password).
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
      .setTitle("Authenticate to Generate Master Key")
      .setSubtitle("Use your biometric credential")
      .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
      .build()

    biometricPrompt.authenticate(promptInfo, cryptoObject)
  }

  /**
   * Access the existing master key using biometric authentication (fingerprint, face unlock, lockscreen pin, etc...).
   * Derives the Key Encryption Key (KEK) using biometric ciphers and uses it to unwrap (decrypt) the master key for use.
   */
  private fun accessMasterKeyUsingBiometrics(
    encryptedMasterKey: ByteArray,
    iv: ByteArray,
    onSuccess: (ByteArray, recoveryKey: String?) -> Unit,
    onFailure: (String) -> Unit
  ) {
    val executor = ContextCompat.getMainExecutor(context)
    val biometricPrompt = BiometricPrompt(activity, executor, object : BiometricPrompt.AuthenticationCallback() {
      override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
        super.onAuthenticationSucceeded(result)
        try {
          val cipher = result.cryptoObject?.cipher
            ?: throw IllegalStateException("Biometric CryptoObject Cipher is null for accessing the master key")

          val masterKey = cipher.doFinal(encryptedMasterKey)
          onSuccess(masterKey, null)
        } catch (e: Exception) {
          onFailure("Biometric Decryption failed: ${e.message}")
        }
      }

      override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
        onFailure("Biometric Authentication error: $errString")
      }

      override fun onAuthenticationFailed() {
        onFailure("Biometric Authentication failed")
      }
    })

    // Get a cipher for decryption
    val cipher = getCipher()

    // Attach the CryptoObject to the BiometricPrompt
    val cryptoObject = BiometricPrompt.CryptoObject(cipher)
    cipher.init(Cipher.DECRYPT_MODE, getOrCreateKeystoreKey(), GCMParameterSpec(128, iv))

    // Lets the user authenticate using either a Class 3 biometric or
    // their lock screen credential (PIN, pattern, or password).
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
      .setTitle("Authenticate to Access Master Key")
      .setSubtitle("Use your biometric credential")
      .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
      .build()

    biometricPrompt.authenticate(promptInfo, cryptoObject)
  }

  @OptIn(ExperimentalUnsignedTypes::class)/**
   * Changes the password used for KEK-wrapped master key protection.
   *
   * This function assumes that both the old and new credentials are password-based (i.e. do not start with the recovery prefix).
   *
   * @param oldPassword The current password.
   * @param newPassword The new password.
   * @param onSuccess Callback indicating the password change was successful.
   * @param onFailure Callback with an error message if something goes wrong.
   */
  fun changePassword(
    oldPassword: String,
    newPassword: String,
    onSuccess: (String) -> Unit,
    onFailure: (String) -> Unit
  ) {
    try {
      // Ensure we're dealing with password credentials (not recovery keys)
      if (oldPassword.startsWith(RECOVERY_KEY_PREFIX) || newPassword.startsWith(RECOVERY_KEY_PREFIX)) {
        onFailure("Recovery keys cannot be used to change passwords")
        return
      }
      // Resolve credential info for the old password.
      val oldInfo = resolveCredentialInfo(oldPassword, context)

      // We expect the password-based storage keys.
      if (oldInfo.encryptedKeyKey != ENCRYPTED_MASTER_KEY_PW_ACCESS_KEY) {
        onFailure("Old credential is not a valid password")
        return
      }

      val encryptedPrefs = getEncryptedPrefs(context)
      val encryptedMasterKeyBase64 = encryptedPrefs.getString(oldInfo.encryptedKeyKey, null)
      val ivBase64 = encryptedPrefs.getString(oldInfo.ivKey, null)

      if (encryptedMasterKeyBase64 == null || ivBase64 == null) {
        onFailure("No password-wrapped master key found")
        return
      }

      // Decode the stored wrapped master key.
      val encryptedMasterKeyBytes = Base64.decode(encryptedMasterKeyBase64, Base64.DEFAULT)
      val ivBytes = Base64.decode(ivBase64, Base64.DEFAULT)
      val wrappedKeyResult = WrappedKeyResult(encryptedMasterKeyBytes, ivBytes)

      // Unwrap the master key using the old KEK.
      val masterKey = unwrapEncryptionKey(wrappedKeyResult, oldInfo.derivedKEK)

      // Derive a new KEK from the new password.
      val newInfo = resolveCredentialInfo(newPassword, context)
      if (newInfo.encryptedKeyKey != ENCRYPTED_MASTER_KEY_PW_ACCESS_KEY) {
        onFailure("New credential is not a valid password")
        return
      }

      // Re-wrap (encrypt) the master key using the new KEK.
      val newWrappedKeyResult = wrapEncryptionKey(masterKey, newInfo.derivedKEK)
      val newEncryptedKeyBase64 = Base64.encodeToString(newWrappedKeyResult.encryptedKey, Base64.DEFAULT)
      val newIvBase64 = Base64.encodeToString(newWrappedKeyResult.wrappingNonce, Base64.DEFAULT)

      // Save the updated wrapped master key and IV to secure storage.
      encryptedPrefs.edit {
        putString(newInfo.encryptedKeyKey, newEncryptedKeyBase64)
        putString(newInfo.ivKey, newIvBase64)
      }

      onSuccess("Password changed successfully")
    } catch (e: Exception) {
      onFailure("Failed to change password: ${e.message}")
    }
  }

  /**
   * Generates a recovery key for the master unlock process.
   * This key should be saved or shown to the user for recovery purposes.
   */
  @OptIn(ExperimentalUnsignedTypes::class)
  fun generateRecoveryKey(): String {
    // Generate a 32-byte random buffer using Libsodium's secure random generator.
    val recoveryKey = LibsodiumRandom.buf(32).toByteArray()
    require(recoveryKey.size == 32) { "Master key must be 32 bytes" }

    // Convert the byte array into a hex string representation.
    val hexKey = recoveryKey.joinToString(separator = "") { byte ->
      "%02x".format(byte)
    }

    // Prepend the custom prefix to help identify the key type.
    return "$RECOVERY_KEY_PREFIX-$hexKey"
  }

  // Get a cipher for encryption and/or decryption
  private fun getCipher(): Cipher {
    val transformation = "$ENCRYPTION_ALGORITHM/$ENCRYPTION_BLOCK_MODE/$ENCRYPTION_PADDING"
    return Cipher.getInstance(transformation)
  }

  private fun getOrCreateKeystoreKey(): SecretKey {
    val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER).apply { load(null) }
    return keyStore.getKey(VAULT_KEYSTORE_ALIAS, null) as? SecretKey
      ?: createKeystoreKey()
  }

  private fun createKeystoreKey(): SecretKey {
    val keyGenerator = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM, ANDROID_KEYSTORE_PROVIDER)
    keyGenerator.init(
      KeyGenParameterSpec.Builder(
        VAULT_KEYSTORE_ALIAS,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
      )
        .setBlockModes(ENCRYPTION_BLOCK_MODE)
        .setEncryptionPaddings(ENCRYPTION_PADDING)
        .setKeySize(ENCRYPTION_KEY_SIZE)
        .setUserAuthenticationRequired(true) // Enforces user authentication
        .setUserAuthenticationParameters(
          0, // Duration for which the key is usable after authentication (0 for immediate re-authentication)
          KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL // Allow both biometrics and device credentials
        )
        .setInvalidatedByBiometricEnrollment(false) // Prevents invalidation when biometrics change
        .build()
    )

    return keyGenerator.generateKey()
  }

  // Generate a nonce for encryption
  @OptIn(ExperimentalUnsignedTypes::class)
  fun generateNonce(): UByteArray = LibsodiumRandom.buf(crypto_secretbox_NONCEBYTES)

  /**
   * Wraps (encrypts) an encryption key using the provided parent key.
   * Returns a WrappedKeyResult containing the encrypted key and its wrapping nonce.
   */
  @OptIn(ExperimentalUnsignedTypes::class)
  fun wrapEncryptionKey(
    key: ByteArray,
    parentKey: ByteArray,
    wrappingNonce: UByteArray = generateNonce()
  ): WrappedKeyResult {
    val (encryptedData, _) = encryptData(key.toUByteArray(), parentKey, wrappingNonce)
    return WrappedKeyResult(encryptedData.toByteArray(), wrappingNonce.toByteArray())
  }

  /**
   * Unwraps (decrypts) an encryption key using the provided parent key and wrapping nonce.
   */
  @OptIn(ExperimentalUnsignedTypes::class)
  fun unwrapEncryptionKey(
    wrappedKey: WrappedKeyResult,
    parentKey: ByteArray
  ): ByteArray {
    return decryptData(
      wrappedKey.encryptedKey.toUByteArray(),
      wrappedKey.wrappingNonce.toUByteArray(),
      parentKey
    ).toByteArray()
  }

  /**
   * Rotates the encryption wrapping for the wrapped key (e.g., a file key).
   *
   * Unwrap the stored key using the parent key and the wrapping nonce,
   * then re-wraps it with a new wrapping nonce. This allows encryption key rotation without re-encrypting
   * the underlying data.
   */
  @OptIn(ExperimentalUnsignedTypes::class)
  fun rotateEncryptionKey(
    wrappedKey: WrappedKeyResult,
    parentKey: ByteArray
  ): WrappedKeyResult  {
    val key = unwrapEncryptionKey(wrappedKey, parentKey)
    val newWrappingNonce = generateNonce()
    return wrapEncryptionKey(key, parentKey, newWrappingNonce)
  }

  /**
   * Re-wraps an encryption key for sharing with a recipient.
   *
   * Implementation approach:
   * 1. Unwrap the wrapped encryption key using the parent key.
   * 2. Seal (asymmetrically encrypt) the raw encryption key using the recipient’s public key.
   *    We use Libsodium's crypto_box_seal (via Box.seal) for this purpose.
   * 3. Return the sealed encryption key.
   */
  @OptIn(ExperimentalUnsignedTypes::class)
  fun wrapEncryptionKeyForSharing(
    wrappedKey: WrappedKeyResult,
    parentKey: ByteArray,
    recipientPublicKey: ByteArray
  ): ByteArray {
    val key = unwrapEncryptionKey(wrappedKey, parentKey)
    val sealed = Box.seal(key.toUByteArray(), recipientPublicKey.toUByteArray())
    return sealed.toByteArray()
  }

  /**
   * Unwraps a shared encryption key that was sealed using LibSodium's Box.seal.
   *
   * Reverses the wrapping done in `wrapEncryptionKeyForSharing`, uses the
   * recipient's key pair (public and private keys) to unseal the wrapped encryption key.
   */
  @OptIn(ExperimentalUnsignedTypes::class)
  fun unwrapSharedEncryptionKey(
    sealedKey: ByteArray,
    recipientPublicKey: ByteArray,
    recipientPrivateKey: ByteArray
  ): ByteArray {
    // Convert input keys to UByteArray and attempt to open the sealed box.
    val unsealedKey = Box.sealOpen(
      sealedKey.toUByteArray(),
      recipientPublicKey.toUByteArray(),
      recipientPrivateKey.toUByteArray()
    )

    // If the unsealing fails, throw an exception.
    if (unsealedKey == null) {
      throw IllegalStateException("Failed to unseal the shared encryption key.")
    }

    // Return the recovered key as a ByteArray.
    return unsealedKey.toByteArray()
  }

  /**
   * Encrypts raw data using LibSodium's SecretBox.
   * Returns a pair of (encryptedData, dataNonce).
   */
  @OptIn(ExperimentalUnsignedTypes::class)
  fun encryptData(
    data: UByteArray,
    key: ByteArray,
    nonce: UByteArray = generateNonce()
  ): Pair<UByteArray, UByteArray> {
    val encryptedData = SecretBox.easy(data, nonce, key.toUByteArray())
    return Pair(encryptedData, nonce) // Save nonce with encrypted data
  }

  /**
   * Decrypts data using LibSodium's SecretBox.
   */
  @OptIn(ExperimentalUnsignedTypes::class)
  fun decryptData(
    encryptedData: UByteArray,
    nonce: UByteArray,
    key: ByteArray
  ): UByteArray = SecretBox.openEasy(encryptedData, nonce, key.toUByteArray())

  /**
   * Appends a ".enc" extension to a file name or path during encryption.
   *
   * @param fileName The original file name or path.
   * @return The file name with ".enc" appended.
   */
  private fun addEncryptionExtension(fileName: String): String = "$fileName.enc"

  /**
   * Removes the ".enc" extension from a file name or path during decryption.
   *
   * @param fileName The file name or path with the ".enc" extension.
   * @return The file name without the ".enc" extension.
   * @throws IllegalArgumentException If the file name does not have a ".enc" extension.
   */
  private fun removeEncryptionExtension(fileName: String): String {
    if (!hasEncryptionExtension(fileName)) {
      throw IllegalArgumentException("File name does not have an .enc extension: $fileName")
    }
    return fileName.removeSuffix(".enc")
  }

  /**
   * Checks if a file name has an ".enc" extension.
   *
   * @param fileName The file name to check.
   * @return True if the file name has an ".enc" extension, false otherwise.
   */
  private fun hasEncryptionExtension(fileName: String): Boolean = fileName.endsWith(".enc")

  /**
   * Encrypts a single DocumentFile by streaming its content into a temporary file in the app's cache.
   * Once encryption is complete, the encrypted file is copied into the target DocumentFile folder with a ".enc" extension,
   * and the temporary file is deleted.
   *
   * @param sourceDocument The original file to encrypt (as a DocumentFile).
   * @param vaultKey The vault key used for encryption.
   * @param context The Android context.
   * @param chunkSize Size of each chunk for streaming encryption.
   * @return The URI of the final encrypted file.
   */
  suspend fun encryptFileUsingTempFolder(
    sourceDocument: DocumentFile,
    vaultKey: ByteArray,
    context: Context,
    chunkSize: Int = 4096
  ): Uri = withContext(Dispatchers.IO) {
    // 1. Create a temporary file in the app's cache directory.
    val tempDir = context.cacheDir
    val tempFile = File.createTempFile("encrypt_temp", null, tempDir)

    // 2. Open an InputStream from the DocumentFile and stream-encrypt its contents into the temporary file.
    context.contentResolver.openInputStream(sourceDocument.uri)?.use { inputStream ->
      FileOutputStream(tempFile).use { fos ->
        // This function is responsible for reading from inputStream, encrypting in chunks,
        // and writing directly to fos.
        encryptStream(inputStream, fos, vaultKey, chunkSize)
      }
    } ?: throw IllegalArgumentException("Unable to open input stream for ${sourceDocument.uri}")

    // 3. Once encryption is complete, create the final encrypted file in the original folder.
    val folder = sourceDocument.parentFile
      ?: throw IllegalArgumentException("Source file has no parent folder")
    val originalName = sourceDocument.name ?: "unknown_file"
    val finalFileName = addEncryptionExtension(originalName)
    val encryptedDocument = folder.createFile("application/octet-stream", finalFileName)
      ?: throw IllegalArgumentException("Failed to create encrypted file in folder")

    // 4. Copy the temporary file into the final DocumentFile.
    context.contentResolver.openOutputStream(encryptedDocument.uri)?.use { finalOut ->
      FileInputStream(tempFile).use { tempIn ->
        tempIn.copyTo(finalOut)
      }
    } ?: throw IllegalArgumentException("Failed to open output stream for ${encryptedDocument.uri}")

    // 5. Clean up: delete the temporary file and optionally the original file.
    tempFile.delete()
    // Optionally delete the original file if desired:
    // sourceDocument.delete()

    encryptedDocument.uri
  }

  /**
   * Streams encryption: reads data from an InputStream, encrypts it in chunks,
   * and writes the encrypted output to an OutputStream.
   */
  @OptIn(ExperimentalUnsignedTypes::class)
  suspend fun encryptStream(
    input: InputStream,
    output: OutputStream,
    key: ByteArray,
    chunkSize: Int = 4096
  ) = withContext(Dispatchers.IO) {
    // Initialize secret stream push state.
    val (state, header) = SecretStream.xChaCha20Poly1305InitPush(key.toUByteArray())
    // Write the header first.
    output.write(header.toByteArray())

    val buffer = ByteArray(chunkSize)
    while (true) {
      if (!coroutineContext.isActive) {
        throw CancellationException("Encryption cancelled.")
      }
      // Optional delay/yield to allow cancellation.
      delay(5)
      yield()

      val bytesRead = input.read(buffer)
      if (bytesRead == -1) break

      val chunk = if (bytesRead < chunkSize) buffer.copyOf(bytesRead) else buffer
      val encryptedChunk = SecretStream.xChaCha20Poly1305Push(
        state,
        chunk.toUByteArray(),
        ubyteArrayOf(),
        crypto_secretstream_xchacha20poly1305_TAG_MESSAGE.toUByte()
      )
      output.write(encryptedChunk.toByteArray())
    }

    // Finalize the stream with the FINAL tag.
    val finalChunk = SecretStream.xChaCha20Poly1305Push(
      state,
      ByteArray(0).toUByteArray(),
      ubyteArrayOf(),
      crypto_secretstream_xchacha20poly1305_TAG_FINAL.toUByte()
    )
    output.write(finalChunk.toByteArray())
  }

  suspend fun encryptVaultFiles(
    vaultId: Long,
    vaultKey: ByteArray,
    context: Context
  ) = withContext(Dispatchers.IO) {
    // 1. Retrieve vault file entries from SQLite for the given vaultId.
    val files = database.getFilesForVault(vaultId)

    files.forEach { fileRecord ->
      // Check if the file is already encrypted (either by a flag or by extension)
      if (fileRecord.isEncrypted) return@forEach

      // 2. Get the DocumentFile representing the file.
      val documentFile = getDocumentFileFromPath(fileRecord.path)
      if (documentFile == null) {
        // Log or handle error: file missing
        return@forEach
      }

      // 3. Encrypt the file using the temporary folder approach.
      val encryptedUri = encryptFileUsingTempFolder(
        sourceDocument = documentFile,
        vaultKey = vaultKey,
        context = context
      )

      // 4. Update the vault record in SQLite.
      database.updateFileEncryptionStatus(
        fileId = fileRecord.id,
        encryptedPath = encryptedUri.toString(),  // new file location
        isEncrypted = true,
        nonce = fileRecord.nonce,         // update with new nonce if applicable
        wrappedKey = fileRecord.wrappedKey // update with new wrapped file key if applicable
      )
    }
  }


  /**
   * Encrypts all files within a DocumentFile folder.
   *
   * For each file:
   * 1. Generate a new random file key.
   * 2. Encrypt the file's content using the file key (via a suspend function that supports cancellation).
   * 3. Wrap the file key using the provided vault key.
   * 4. Create a new file with an appended ".enc" extension and write the encrypted data.
   *
   * Returns a map from the encrypted file's URI to a pair of (wrapped file key, file nonce)
   * so that this metadata can be stored in the database.
   */
  @OptIn(ExperimentalUnsignedTypes::class)
  suspend fun encryptDocumentFolder(
    folder: DocumentFile,
    vaultKey: ByteArray,
  ): Map<Uri, FileEncryptionResult> {
    val resultMap = mutableMapOf<Uri, Pair<ByteArray, ByteArray>>()
    for (file in folder.listFiles()) {
      if (file.isFile) {
        // Read original file data.
        val fileData = context.contentResolver.openInputStream(file.uri)?.readBytes()
          ?: continue

        // Generate a new random file key.
        val fileKey = LibsodiumRandom.buf(32).toByteArray()

        // Encrypt the file data using the file key with cancellation support.
        val (encryptedData, fileDataNonce) = encryptDataInChunks(fileData, fileKey)

        // Wrap the file key with the vault key.
        val wrappedFileKey = wrapEncryptionKey(fileKey, vaultKey)

        // Create a new file with ".enc" appended to its name.
        val originalName = file.name ?: "unknown_file"
        val encryptedFileName = addEncryptionExtension(originalName)
        val encryptedFile = folder.createFile("application/octet-stream", encryptedFileName)
          ?: continue

        // Write the encrypted data.
        context.contentResolver.openOutputStream(encryptedFile.uri)?.use {
          it.write(encryptedData)
        }
        // Map the encrypted file URI to its wrapped file key and nonce.
        resultMap[encryptedFile.uri] = FileEncryptionResult(
          wrappedFileKey = wrappedFileKey,
          dataNonce = fileDataNonce,
          encryptedFileData = encryptedData
        )
      }
    }

    return resultMap
  }

  /**
   * Decrypts all files in the folder and restores their original content.
   * Preserves the folder structure using DocumentFile.
   *
   * @param encryptedFolder The DocumentFile representing the encrypted folder.
   * @param vaultKey The key used to decrypt the individual files.
   * @param masterKey The key used to decrypt the folder encryption metadata.
   * @param vaultNonce The nonce used for decrypting the vault metadata.
   * @return A DocumentFile representing the decrypted folder.
   */
  @OptIn(ExperimentalUnsignedTypes::class)
  fun decryptDocumentFolder(
    encryptedFolder: DocumentFile,
    vaultKey: ByteArray,
    masterKey: ByteArray,
    vaultNonce: ByteArray
  ): DocumentFile {
    encryptedFolder.listFiles().forEach { file ->
      if (file.isFile) {

        val fileName = file.name ?: "unknown_file"
        if (!hasEncryptionExtension(fileName)) return@forEach

        val decryptedFileName = removeEncryptionExtension(fileName)
        val decryptedFile = encryptedFolder.createFile("application/octet-stream", decryptedFileName)
          ?: throw IllegalArgumentException("Failed to create decrypted file: $decryptedFileName")

        // Read the encrypted file
        val lockedEncryptedData = context.contentResolver.openInputStream(file.uri)?.readBytes()
          ?: throw IllegalArgumentException("Failed to read file data: ${file.uri}")

        // Remove the master key lock
        val unlockedEncryptedData = decryptData(
          lockedEncryptedData.toUByteArray(),
          vaultNonce.toUByteArray(),
          masterKey
        )

        // Extract nonce and encrypted data
        val nonce = unlockedEncryptedData.sliceArray(0 until crypto_secretbox_NONCEBYTES)
        val encryptedData = unlockedEncryptedData.sliceArray(crypto_secretbox_NONCEBYTES until unlockedEncryptedData.size)

        // Decrypt the file content using the vault key
        val decryptedData = decryptData(
          encryptedData.toUByteArray(),
          nonce.toUByteArray(),
          vaultKey
        )

        // Write the decrypted content to the new file
        context.contentResolver.openOutputStream(decryptedFile.uri)?.use {
          it.write(decryptedData.toByteArray())
        }
      }
    }

    return encryptedFolder
  }

  /**
   * Retrieves a DocumentFile representing a folder based on the provided URI.
   * Ensures the folder is accessible and persists permissions for future access.
   *
   * @param folderUri The SAF URI for the folder.
   * @param persistPermissions Whether to persist read/write permissions for the folder URI.
   * @return The DocumentFile object representing the folder.
   * @throws IllegalArgumentException If the URI is invalid or the folder does not exist.
   */
  fun getDocumentFolder(folderUri: Uri, persistPermissions: Boolean = true): DocumentFile {
    // Persist permissions if requested
    if (persistPermissions) {
      try {
        context.contentResolver.takePersistableUriPermission(
          folderUri,
          Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        )
      } catch (e: SecurityException) {
        throw IllegalArgumentException("Failed to persist permissions for URI: $folderUri", e)
      }
    }

    // Retrieve the DocumentFile for the folder
    val documentFolder = DocumentFile.fromTreeUri(context, folderUri)

    // Validate the folder
    if (documentFolder == null || !documentFolder.isDirectory) {
      throw IllegalArgumentException("The folder does not exist or is not a valid directory: $folderUri")
    }

    // Check if the folder is accessible
    if (!isUriAccessible(documentFolder.uri)) {
      throw IllegalArgumentException("The folder is not accessible: $folderUri")
    }

    return documentFolder
  }

  /**
   * Checks if a URI is accessible by attempting to open a stream.
   *
   * @param uri The URI to check.
   * @return True if the URI is accessible, false otherwise.
   */
  private fun isUriAccessible(uri: Uri): Boolean {
    return try {
      context.contentResolver.openInputStream(uri)?.use { true } ?: false
    } catch (e: Exception) {
      false
    }
  }

}
