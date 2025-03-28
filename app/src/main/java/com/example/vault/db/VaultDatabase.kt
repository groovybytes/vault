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
    val vaultNonce: ByteArray,
    val mode: String
)

// Data class representing a File entry within a Vault.
data class FileEntry(
    val id: Int? = null,
    val vaultId: Int,
    val filePath: String,
    val encryptedFileKey: ByteArray,
    val fileKeyNonce: ByteArray,
    val fileNonce: ByteArray,
    val mode: String
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
                VAULT_NONCE BLOB NOT NULL,
                MODE TEXT NOT NULL
            )
            """
        )
        // Create the Files table.
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS Files (
                ID INTEGER PRIMARY KEY AUTOINCREMENT,
                VAULT_ID INTEGER NOT NULL,
                FILE_PATH TEXT NOT NULL,
                ENCRYPTED_FILE_KEY BLOB NOT NULL,
                FILE_KEY_NONCE BLOB NOT NULL,
                FILE_NONCE BLOB NOT NULL,
                MODE TEXT NOT NULL,
                FOREIGN KEY (VAULT_ID) REFERENCES Vaults(ID) ON DELETE CASCADE
            )
            """
        )
    }

    override fun onUpgrade(db: SQLiteDatabase?, v1: Int, v2: Int) {
        // Drop the existing table and recreate it (for simplicity in upgrades)
        db!!.execSQL("DROP TABLE IF EXISTS Vaults")
        db.execSQL("DROP TABLE IF EXISTS Vaults")
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
            put("MODE", vault.mode)
        }

        sqLiteDatabase.insert("Vaults", null, contentValues)
    }

    fun updateVault(vault: Vault) {
        val sqLiteDatabase = this.writableDatabase
        val contentValues = ContentValues().apply {
            put("PATH", vault.path)
            put("TITLE", vault.title)
            put("DESCRIPTION", vault.description)
            put("ENCRYPTED_KEY", vault.encryptedKey)
            put("VAULT_NONCE", vault.vaultNonce)
            put("MODE", vault.mode)
        }

        sqLiteDatabase.update("Vaults", contentValues, "ID = ?", arrayOf(vault.id.toString()))
    }

    fun deleteVault(id: Int) {
        val sqLiteDatabase = this.writableDatabase
        sqLiteDatabase.delete("Vaults", "ID = ?", arrayOf(id.toString()))
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
        val MODE_COL = results.getColumnIndex("MODE")

        while (results.moveToNext()) {
            val id = results.getInt(ID_COL)
            val title = results.getString(TITLE_COL)
            val description = results.getString(DESCRIPTION_COL)

            val path = results.getString(PATH_COL)
            val encryptedKey = results.getBlob(ENCRYPTED_KEY_COL)
            val vaultNonce = results.getBlob(VAULT_NONCE_COL)
            val mode = results.getString(MODE_COL)

            vaults.add(
                Vault(
                    id=id,
                    title=title,
                    description=description,
                    path=path,
                    encryptedKey=encryptedKey,
                    vaultNonce=vaultNonce,
                    mode=mode
                )
            )
        }

        results.close()
        return vaults
    }

    // FileEntry CRUD operations.
    fun addFileEntry(fileEntry: FileEntry) {
        val sqLiteDatabase = this.writableDatabase
        val contentValues = ContentValues().apply {
            put("VAULT_ID", fileEntry.vaultId)
            put("FILE_PATH", fileEntry.filePath)
            put("ENCRYPTED_FILE_KEY", fileEntry.encryptedFileKey)
            put("FILE_KEY_NONCE", fileEntry.fileKeyNonce)
            put("FILE_NONCE", fileEntry.fileNonce)
            put("MODE", fileEntry.mode)
        }
        sqLiteDatabase.insert("Files", null, contentValues)
    }

    fun updateFileEntry(fileEntry: FileEntry) {
        val sqLiteDatabase = this.writableDatabase
        val contentValues = ContentValues().apply {
            put("VAULT_ID", fileEntry.vaultId)
            put("FILE_PATH", fileEntry.filePath)
            put("ENCRYPTED_FILE_KEY", fileEntry.encryptedFileKey)
            put("FILE_KEY_NONCE", fileEntry.fileKeyNonce)
            put("FILE_NONCE", fileEntry.fileNonce)
            put("MODE", fileEntry.mode)
        }
        sqLiteDatabase.update("Files", contentValues, "ID = ?", arrayOf(fileEntry.id.toString()))
    }

    fun deleteFileEntry(id: Int) {
        val sqLiteDatabase = this.writableDatabase
        sqLiteDatabase.delete("Files", "ID = ?", arrayOf(id.toString()))
    }

    fun getFileEntries(vaultId: Int): List<FileEntry> {
        val sqLiteDatabase = this.readableDatabase
        val fileEntries = mutableListOf<FileEntry>()

        val results = sqLiteDatabase.rawQuery("SELECT * FROM Files WHERE VAULT_ID = ?", arrayOf(vaultId.toString()))

        val ID_COL = results.getColumnIndex("ID")
        val FILE_PATH_COL = results.getColumnIndex("FILE_PATH")
        val ENCRYPTED_FILE_KEY_COL = results.getColumnIndex("ENCRYPTED_FILE_KEY")
        val FILE_KEY_NONCE_COL = results.getColumnIndex("FILE_KEY_NONCE_COL")
        val FILE_NONCE_COL = results.getColumnIndex("FILE_NONCE")
        val MODE_COL = results.getColumnIndex("MODE")

        while (results.moveToNext()) {
            val id = results.getInt(ID_COL)
            val filePath = results.getString(FILE_PATH_COL)
            val encryptedFileKey = results.getBlob(ENCRYPTED_FILE_KEY_COL)
            val fileKeyNonce = results.getBlob(FILE_KEY_NONCE_COL)
            val fileNonce = results.getBlob(FILE_NONCE_COL)
            val mode = results.getString(MODE_COL)

            fileEntries.add(
                FileEntry(
                    id=id,
                    vaultId = vaultId,
                    filePath = filePath,
                    encryptedFileKey = encryptedFileKey,
                    fileKeyNonce = fileKeyNonce,
                    fileNonce = fileNonce,
                    mode = mode
                )
            )
        }

        results.close()
        return fileEntries
    }
}

