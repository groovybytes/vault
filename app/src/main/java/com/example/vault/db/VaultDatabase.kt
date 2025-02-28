package com.example.vault.db

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

// Data class representing a Vault.
data class Vault(
    val id: Int? = null, // ID is optional for new Vaults (auto-generated)
    val title: String,
    val description: String? = null,

    val path: String,
    val encryptedKey: ByteArray,
    val vaultNonce: ByteArray
)

class VaultDatabase(context : Context?, name : String?, factory : SQLiteDatabase.CursorFactory?, version: Int = 1) : SQLiteOpenHelper(context, name, factory, version) {

    override fun onCreate(db: SQLiteDatabase?) {
        // Create the Vaults table with new fields for path, encrypted key, and nonces
        db!!.execSQL(
            """
            CREATE TABLE IF NOT EXISTS Vaults (
                ID INTEGER PRIMARY KEY AUTOINCREMENT,
                TITLE TEXT NOT NULL,
                PATH TEXT NOT NULL,
                DESCRIPTION TEXT,
                ENCRYPTED_KEY BLOB NOT NULL,
                VAULT_NONCE BLOB NOT NULL
            )
            """
        )
    }

    override fun onUpgrade(db: SQLiteDatabase?, v1: Int, v2: Int) {
        // Drop the existing table and recreate it (for simplicity in upgrades)
        db!!.execSQL("DROP TABLE IF EXISTS Vaults")
        onCreate(db)
    }

    // Adds a new Vault to the database.
    fun addVault(vault: Vault) {
        val sqLiteDatabase = this.writableDatabase
        val contentValues = ContentValues().apply {
            put("PATH", vault.path)
            put("TITLE", vault.title)
            put("DESCRIPTION", vault.description)
            put("ENCRYPTED_KEY", vault.encryptedKey)
            put("VAULT_NONCE", vault.vaultNonce)
        }

        sqLiteDatabase.insert("Vaults", null, contentValues)
    }

    // Retrieves all vaults from the database.
    fun getVaults(): List<Vault> {
        return getVaultsByQuery("SELECT * FROM Vaults", null)
    }

    // Searches vaults by path (partial match).
    fun searchVaults(searchQuery: String): List<Vault> {
        return getVaultsByQuery("SELECT * FROM Vaults WHERE PATH LIKE ?", arrayOf("%$searchQuery%"))
    }

    private fun getVaultsByQuery(query: String, args: Array<String>?): List<Vault> {
        val sqLiteDatabase = this.readableDatabase
        val vaults = mutableListOf<Vault>()

        val results = sqLiteDatabase.rawQuery(query, args)

        val ID_COL = results.getColumnIndex("ID")
        val TITLE_COL = results.getColumnIndex("TITLE")
        val DESCRIPTION_COL = results.getColumnIndex("DESCRIPTION")

        val PATH_COL = results.getColumnIndex("PATH")
        val ENCRYPTED_KEY_COL = results.getColumnIndex("ENCRYPTED_KEY")
        val VAULT_NONCE_COL = results.getColumnIndex("VAULT_NONCE")

        while (results.moveToNext()) {
            val id = results.getInt(ID_COL)
            val title = results.getString(TITLE_COL)
            val description = results.getString(DESCRIPTION_COL)

            val path = results.getString(PATH_COL)
            val encryptedKey = results.getBlob(ENCRYPTED_KEY_COL)
            val vaultNonce = results.getBlob(VAULT_NONCE_COL)

            vaults.add(Vault(id, path, title, description, encryptedKey, vaultNonce))
        }

        results.close()
        return vaults
    }

}

