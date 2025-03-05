package com.example.vault

import android.annotation.SuppressLint
import android.content.Context
import android.net.Uri
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.recyclerview.widget.RecyclerView
import com.example.vault.db.Vault
import com.example.vault.db.VaultDatabase
import com.ionspin.kotlin.crypto.util.encodeToUByteArray
import java.nio.charset.Charset

class VaultViewAdapter(private var db: VaultDatabase, private var keyVault: SecureKeyVault, private var context: Context) : RecyclerView.Adapter<VaultViewAdapter.VaultViewHolder>() {

    private var vaultList: List<Vault> = db.getVaults()

    //view holder class
    class VaultViewHolder(vaultView: View) : RecyclerView.ViewHolder(vaultView) {
        val titleOutput: TextView = vaultView.findViewById(R.id.titleView)
        val contentOutput: TextView = vaultView.findViewById(R.id.contentView)
        val buttonDecrypt: Button = vaultView.findViewById(R.id.buttonDecrypt)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VaultViewHolder {
        val viewRValue = R.layout.vault_thumbnail_view
        return VaultViewHolder(
            LayoutInflater.from(parent.context)
                .inflate(R.layout.vault_thumbnail_view, parent, false)
        )
    }

    override fun getItemCount(): Int {
        return vaultList?.size ?: -1
    }

    private fun updateStyle(holder: VaultViewHolder, vault: Vault) {
        holder.titleOutput.text = vault.title
        holder.contentOutput.text = vault.description
        holder.buttonDecrypt.text = if (vault.mode == "encrypted") "Decrypt" else "Encrypt"
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    override fun onBindViewHolder(holder: VaultViewHolder, position: Int) {
        val vault : Vault = vaultList[position]
        val title = vault.title

        val currentPath = vault.path
        val encryptedKey = vault.encryptedKey
        val vaultNonce = vault.vaultNonce
        val mode = vault.mode

        println("Vault: $vault")

        updateStyle(holder, vault)

        holder.buttonDecrypt.setOnClickListener {
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

                        val encryptedFolderUri = Uri.parse(currentPath)
                        val encryptedDocumentFolder = keyVault.getDocumentFolder(encryptedFolderUri, persistPermissions = true)

                        println("Folder: $encryptedDocumentFolder")
                        println("folderUri: $encryptedFolderUri")

                        var updatedVault: Vault
                        if (mode == "encrypted") {
                            // Decrypt the folder
                            val decryptedFolder = keyVault.decryptDocumentFolder(
                                encryptedFolder = encryptedDocumentFolder,
                                vaultKey = encryptedKey,
                                masterKey = masterKey,
                                vaultNonce = vaultNonce
                            )

                            updatedVault = vault.copy(mode = "decrypted")
                            db.updateVault(updatedVault)
                            println("Folder decrypted at: ${decryptedFolder.uri}")

                        } else {
                            // Encrypt the folder
                            val (encryptedFolder) = keyVault.encryptDocumentFolder(
                                folder = encryptedDocumentFolder,
                                vaultKey = masterKey,
                                masterKey = masterKey,
                                vaultNonce = vaultNonce.toUByteArray()
                            )

                            updatedVault = vault.copy(mode = "encrypted")
                            db.updateVault(updatedVault)
                            println("Folder encrypted at: ${encryptedFolder.uri}")
                        }

                        updateStyle(holder, updatedVault)
                        Toast.makeText(context, "Authentication successful", Toast.LENGTH_LONG).show()

                    },
                    onFailure = { error ->
                        println("Authentication failed or master key not found")
                        println(error)

                        Toast.makeText(context, "Authentication failed", Toast.LENGTH_LONG).show()
                    }
                )
            }
        }
    }

    @SuppressLint("NotifyDataSetChanged") //entire dataset can change
    fun updateVaultList(newList: List<Vault>? = null) {
        vaultList = newList ?: db.getVaults()
        notifyDataSetChanged()
    }

    fun updateVaultValue(position: Int, vault: Vault) {
        db.updateVault(vault)
        notifyItemChanged(position)
    }

}