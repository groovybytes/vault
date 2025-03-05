package com.example.vault.ui.folderpicker

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.documentfile.provider.DocumentFile
import androidx.fragment.app.Fragment
import androidx.navigation.fragment.findNavController
import com.example.vault.SecureKeyVault
import com.example.vault.db.VaultDatabase
import com.example.vault.databinding.FragmentFolderpickerBinding
import com.example.vault.db.Vault
import com.ionspin.kotlin.crypto.util.encodeToUByteArray
import java.nio.charset.Charset

class FolderPickerFragment : Fragment() {

    private var _db: VaultDatabase? = null
    private var currentPath: String? = null
    private lateinit var folderContentsTextView: TextView
    private lateinit var binding: FragmentFolderpickerBinding
    private lateinit var keyVault: SecureKeyVault

    @OptIn(ExperimentalUnsignedTypes::class)
    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        super.onCreateView(inflater, container, savedInstanceState)
        binding = FragmentFolderpickerBinding.inflate(inflater, container, false)

        _db = VaultDatabase(activity, "vaultdb", null)

        // Initialize UI elements
        val folderPickerBtn: Button = binding.folderPickerButton
        val encryptBtn: Button = binding.encryptButton
        folderContentsTextView = binding.folderContentsTextView

        keyVault = SecureKeyVault(requireContext(), this)
        keyVault.init {}

        folderPickerBtn.setOnClickListener {
            openFolderPicker()
        }
        encryptBtn.setOnClickListener {
            val title = binding.editText.text.toString()
            println("Encrypt Title: $title")
            println("Encrypt Current path: $currentPath")
            if (currentPath == null) {
                Toast.makeText(activity, "You must choose a folder first!", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            //todo: add encryption functionality
            keyVault.init {
                keyVault.authenticate(
                    onSuccess = { masterKey ->

                        val message = "Hello, world!".encodeToUByteArray()
                        val (encryptedData, nonce) = keyVault.encryptData(message, masterKey)
                        println("Encrypted data: $encryptedData")

                        val decryptedData = keyVault.decryptData(encryptedData, nonce, masterKey)
                        println("Decrypted data bytes: $decryptedData")
                        println("Decrypted data: ${String(decryptedData.toByteArray(), Charset.forName("UTF-8"))}")

                        val folderUri = Uri.parse(currentPath)
                        val documentFolder = keyVault.getDocumentFolder(folderUri, persistPermissions = true)

                        println("Folder: $documentFolder")
                        println("folderUri: $folderUri")

                        // Encrypt the folder
                        val (encryptedFolder, vaultNonce) = keyVault.encryptDocumentFolder(
                            folder = documentFolder,
                            vaultKey = masterKey,
                            masterKey = masterKey,
                        )

                        val vault = Vault(
                            title=title,
                            description = "Encrypted folder: $title",
                            path=encryptedFolder.uri.toString(),
                            encryptedKey=masterKey,
                            vaultNonce=vaultNonce,
                            mode="encrypted"
                        )

                        _db!!.addVault(vault)
                        println("Folder encrypted at: ${encryptedFolder.uri}")

                        Toast.makeText(context, "Authentication successful", Toast.LENGTH_LONG).show()
                        this@FolderPickerFragment.findNavController().navigateUp()

                    },
                    onFailure = { error ->
                        println("Authentication failed or master key not found")
                        println(error)

                        Toast.makeText(context, "Authentication failed", Toast.LENGTH_LONG).show()
                        this@FolderPickerFragment.findNavController().navigateUp()
                    }
                )
            }
        }

        return binding.root
    }

    private fun openFolderPicker() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
            addFlags(
                Intent.FLAG_GRANT_READ_URI_PERMISSION or
                        Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                        Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
            )
        }
        folderPickerLauncher.launch(intent)
    }

    //handle folder picker result
    private val folderPickerLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            result.data?.data?.let { uri ->
                Log.i("FolderPicker", "Directory tree: $uri")
                currentPath = uri.toString() // Store the full URI string
                persistFolderPermission(uri) // Persist permissions for the selected folder
                displayContents(uri)
            } ?: run {
                Log.e("FolderPicker", "No folder selected.")
            }
        } else {
            Log.e("FolderPicker", "Folder picker canceled.")
        }
    }

    private fun persistFolderPermission(uri: Uri) {
        try {
            val takeFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            requireContext().contentResolver.takePersistableUriPermission(uri, takeFlags)
            Log.i("FolderPicker", "Persisted permissions for URI: $uri")
        } catch (e: SecurityException) {
            Log.e("FolderPicker", "Failed to persist permissions for URI: $uri", e)
        }
    }

    private fun displayContents(folderUri: Uri) {
        val documentFile = DocumentFile.fromTreeUri(requireContext(), folderUri)
        if (documentFile != null && documentFile.isDirectory) {
            currentPath = folderUri.toString() // Use the SAF URI as the path
            val fileNames = documentFile.listFiles().joinToString("\n") { it.name ?: "Unnamed file" }

            folderContentsTextView.text = fileNames ?: "No files found in the selected folder."
            Log.i("FolderPicker", "Files in directory:\n$fileNames")
        } else {
            Log.e("FolderPicker", "Invalid folder URI: $folderUri")
            Toast.makeText(context, "Invalid folder selected", Toast.LENGTH_SHORT).show()
        }
    }

}