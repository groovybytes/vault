package com.example.vault

import android.annotation.SuppressLint
import android.net.Uri
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.example.vault.db.Vault
import com.ionspin.kotlin.crypto.util.encodeToUByteArray
import java.nio.charset.Charset

class VaultViewAdapter(private var vaultList : List<Vault>, private var keyVault: SecureKeyVault) : RecyclerView.Adapter<VaultViewAdapter.VaultViewHolder>() {

    //view holder class
    class VaultViewHolder(vaultView: View) : RecyclerView.ViewHolder(vaultView) {
        val titleOutput: TextView = vaultView.findViewById(R.id.titleView)
        val contentOutput: TextView = vaultView.findViewById(R.id.contentView)
        val buttonDecrypt: Button = vaultView.findViewById(R.id.buttonDecrypt)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VaultViewHolder {
        val viewRValue = R.layout.vault_thumbnail_view
        return VaultViewHolder(
            LayoutInflater.from(parent.context).inflate(R.layout.vault_thumbnail_view, parent, false)
        )
    }

    override fun getItemCount(): Int {
        return vaultList.size
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    override fun onBindViewHolder(holder: VaultViewHolder, position: Int) {
        val vault : Vault = vaultList[position]
        val title = vault.title

        val currentPath = vault.path
        val encryptedKey = vault.encryptedKey
        val vaultNonce = vault.vaultNonce

        holder.titleOutput.text = title
        holder.contentOutput.text = vault.description

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
                        val encryptedDocumentFolder = keyVault.getDocumentFolder(encryptedFolderUri)

                        println("Folder: $encryptedDocumentFolder")
                        println("folderUri: $encryptedFolderUri")

                        // Decrypt the folder
                        val decryptedFolder = keyVault.decryptDocumentFolder(
                            encryptedFolder = encryptedDocumentFolder,
                            vaultKey = encryptedKey,
                            masterKey = masterKey,
                            vaultNonce = vaultNonce
                        )
                        println("Folder decrypted at: ${decryptedFolder.uri}")

//                        Toast.makeText(context, "Authentication successful", Toast.LENGTH_LONG).show()

                    },
                    onFailure = { error ->
                        println("Authentication failed or master key not found")
                        println(error)

//                        Toast.makeText(requiredContext(), "Authentication failed", Toast.LENGTH_LONG).show()
                    }
                )
            }
        }
    }

    @SuppressLint("NotifyDataSetChanged") //entire dataset can change
    fun updateVaultList(newList: List<Vault>) {
        vaultList = newList
        notifyDataSetChanged()
    }

}