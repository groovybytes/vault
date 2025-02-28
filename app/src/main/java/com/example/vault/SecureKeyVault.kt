package com.example.vault

import android.content.Context
import android.content.SharedPreferences
import android.net.Uri
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.documentfile.provider.DocumentFile
import androidx.fragment.app.Fragment
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import com.ionspin.kotlin.crypto.LibsodiumInitializer
import com.ionspin.kotlin.crypto.secretbox.SecretBox
import com.ionspin.kotlin.crypto.secretbox.crypto_secretbox_NONCEBYTES
import com.ionspin.kotlin.crypto.util.LibsodiumRandom
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class SecureKeyVault(private val context: Context, private val activity: Fragment) {

    companion object {
        private const val ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val VAULT_KEYSTORE_ALIAS = "VaultKeyStoreAlias"
        private const val VAULT_PREFS_ACCESS_KEY = "VaultSharedPrefs"
        private const val ENCRYPTED_MASTER_KEY_ACCESS_KEY = "EncryptedMasterKey"
        private const val INITIALIZATION_VECTOR_ACCESS_KEY = "InitializationVector"
        private val MASTER_KEY_ALIAS = MasterKeys.AES256_GCM_SPEC

        private const val ENCRYPTION_BLOCK_MODE = KeyProperties.BLOCK_MODE_GCM
        private const val ENCRYPTION_PADDING = KeyProperties.ENCRYPTION_PADDING_NONE
        private const val ENCRYPTION_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
        private const val ENCRYPTION_KEY_SIZE = 256
    }

    // Initialize Libsodium
    fun init(callback: () -> Unit) {
        if (!LibsodiumInitializer.isInitialized()) {
            LibsodiumInitializer.initializeWithCallback(callback)
        } else {
            callback()
        }
    }

    // Create EncryptedSharedPreferences instance
    private fun getEncryptedPrefs(): SharedPreferences {
        val masterKeyAlias = MasterKeys.getOrCreate(MASTER_KEY_ALIAS)
        return EncryptedSharedPreferences.create(
            VAULT_PREFS_ACCESS_KEY,
            masterKeyAlias,
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    // Retrieve or generate a master key
    fun authenticate(
        onSuccess: (ByteArray) -> Unit,
        onFailure: (String) -> Unit
    ) {
        val encryptedPrefs = getEncryptedPrefs()

        // Check if master key exists
        val encryptedMasterKeyBase64 = encryptedPrefs.getString(ENCRYPTED_MASTER_KEY_ACCESS_KEY, null)
        val masterKeyInitializationVectorBase64 = encryptedPrefs.getString(INITIALIZATION_VECTOR_ACCESS_KEY, null)
        if (encryptedMasterKeyBase64 != null && masterKeyInitializationVectorBase64 != null) {
            // Decrypt and return the existing master key
            val encryptedMasterKey = Base64.decode(encryptedMasterKeyBase64, Base64.DEFAULT)
            val iv = Base64.decode(masterKeyInitializationVectorBase64, Base64.DEFAULT)
            accessMasterKeyUsingBiometrics(encryptedMasterKey, iv, onSuccess, onFailure)
        } else {
            // Generate and store a new master key
            generateMasterKeyUsingBiometrics(encryptedPrefs, onSuccess, onFailure)
        }
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    private fun generateMasterKeyUsingBiometrics(
        encryptedPrefs: SharedPreferences,
        onSuccess: (ByteArray) -> Unit,
        onFailure: (String) -> Unit
    ) {
        val executor = ContextCompat.getMainExecutor(context)
        val biometricPrompt = BiometricPrompt(activity, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                try {
                    val cipher = result.cryptoObject?.cipher
                        ?: throw IllegalStateException("CryptoObject Cipher is null")

                    // Generate a 32-byte master key using LibSodium
                    val masterKey = LibsodiumRandom.buf(32).toByteArray()
                    require(masterKey.size == 32) { "Master key must be 32 bytes" }

                    // Encrypt the master key using the Keystore
                    val encryptedMasterKey = cipher.doFinal(masterKey)
                    val iv = cipher.iv

                    val encryptedMasterKeyBase64 = Base64.encodeToString(encryptedMasterKey, Base64.DEFAULT)
                    val ivBase64 = Base64.encodeToString(iv, Base64.DEFAULT)

                    // Store the encrypted master key
                    encryptedPrefs.edit().run {
                        putString(ENCRYPTED_MASTER_KEY_ACCESS_KEY, encryptedMasterKeyBase64)
                        putString(INITIALIZATION_VECTOR_ACCESS_KEY, ivBase64)
                    }.apply()
                    onSuccess(masterKey)
                } catch (e: Exception) {
                    onFailure("Failed to generate and store master key: ${e.message}")
                }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                onFailure("Authentication error: $errString")
            }

            override fun onAuthenticationFailed() {
                onFailure("Authentication failed")
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

    private fun accessMasterKeyUsingBiometrics(
        encryptedMasterKey: ByteArray,
        iv: ByteArray,
        onSuccess: (ByteArray) -> Unit,
        onFailure: (String) -> Unit
    ) {
        val executor = ContextCompat.getMainExecutor(context)
        val biometricPrompt = BiometricPrompt(activity, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                try {
                    val cipher = result.cryptoObject?.cipher
                        ?: throw IllegalStateException("CryptoObject Cipher is null")

                    val masterKey = cipher.doFinal(encryptedMasterKey)
                    onSuccess(masterKey)
                } catch (e: Exception) {
                    onFailure("Decryption failed: ${e.message}")
                }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                onFailure("Authentication error: $errString")
            }

            override fun onAuthenticationFailed() {
                onFailure("Authentication failed")
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
                .setInvalidatedByBiometricEnrollment(false) // Prevents invalidation when biometrics change
                .build()
        )

        return keyGenerator.generateKey()
    }

    // Generate a nonce for encryption
    @OptIn(ExperimentalUnsignedTypes::class)
    fun generateNonce(): UByteArray {
        return LibsodiumRandom.buf(crypto_secretbox_NONCEBYTES)
    }

    // Encrypts data using Libsodium and the master key fetched from EncryptedSharedPreferences.
    @OptIn(ExperimentalUnsignedTypes::class)
    fun encryptData(
        data: UByteArray,
        masterKey: ByteArray,
        nonce: UByteArray = generateNonce()
    ): Pair<UByteArray, UByteArray> {
        val encryptedData = SecretBox.easy(data, nonce, masterKey.toUByteArray())
        return Pair(encryptedData, nonce) // Save nonce with encrypted data
    }

    // Decrypts data using Libsodium and the master key fetched from EncryptedSharedPreferences.
    @OptIn(ExperimentalUnsignedTypes::class)
    fun decryptData(encryptedData: UByteArray, nonce: UByteArray, masterKey: ByteArray): UByteArray {
        return SecretBox.openEasy(encryptedData, nonce, masterKey.toUByteArray())
    }

    /**
     * Appends a ".enc" extension to a file name or path during encryption.
     *
     * @param fileName The original file name or path.
     * @return The file name with ".enc" appended.
     */
    private fun addEncryptionExtension(fileName: String): String {
        return "$fileName.enc"
    }

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
    private fun hasEncryptionExtension(fileName: String): Boolean {
        return fileName.endsWith(".enc")
    }

    /**
     * Encrypts all files in the folder and saves them with encrypted content.
     * Preserves the folder structure using DocumentFile.
     */
    @OptIn(ExperimentalUnsignedTypes::class)
    fun encryptDocumentFolder(folder: DocumentFile, vaultKey: ByteArray, masterKey: ByteArray): Pair<DocumentFile, ByteArray> {
        val vaultNonce = generateNonce()
        folder.listFiles().forEach { file ->
            if (file.isFile) {

                val fileName = file.name ?: "unknown_file"
                val encryptedFileName = addEncryptionExtension(fileName)
                val encryptedFile = folder.createFile("application/octet-stream", encryptedFileName)
                    ?: throw IllegalArgumentException("Failed to create encrypted file: $encryptedFileName")

                val fileData = context.contentResolver.openInputStream(file.uri)?.readBytes()
                    ?: throw IllegalArgumentException("Failed to read file data: ${file.uri}")

                val (encryptedData, nonce) = encryptData(fileData.toUByteArray(), vaultKey)
                val (lockedData) = encryptData((nonce + encryptedData), masterKey, vaultNonce)

                // Save nonce + encrypted content in the encrypted file
                context.contentResolver.openOutputStream(encryptedFile.uri)?.use {
                    it.write(lockedData.toByteArray())
                }
            }
        }

        return Pair(folder, vaultNonce.toByteArray())
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
     *
     * @param folderUri The SAF URI for the folder.
     * @return The DocumentFile object representing the folder.
     * @throws IllegalArgumentException If the URI is invalid or the folder does not exist.
     */
    fun getDocumentFolder(folderUri: Uri): DocumentFile {
        val documentFolder = DocumentFile.fromTreeUri(context, folderUri)

        // Ensure the folder exists
        if (documentFolder == null || !documentFolder.isDirectory) {
            throw IllegalArgumentException("The folder does not exist or is not a valid directory: $folderUri")
        }

        return documentFolder
    }
}
