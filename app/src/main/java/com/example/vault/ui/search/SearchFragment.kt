package com.example.vault.ui.search

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.appcompat.widget.SearchView
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import com.example.vault.SecureKeyVault
import com.example.vault.db.Vault
import com.example.vault.db.VaultDatabase
import com.example.vault.VaultViewAdapter
import com.example.vault.databinding.FragmentSearchBinding

class SearchFragment : Fragment() {

    private var _binding: FragmentSearchBinding? = null
    private var _db : VaultDatabase? = null
    private var _vaultAdapter : VaultViewAdapter? = null
    private lateinit var keyVault: SecureKeyVault

    // This property is only valid between onCreateView and
    // onDestroyView.
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {

        _binding = FragmentSearchBinding.inflate(inflater, container, false)

        _db = VaultDatabase(activity, "vaultdb", null)

        keyVault = SecureKeyVault(requireContext(), this)
        keyVault.init {}

        _vaultAdapter = VaultViewAdapter(_db!!, keyVault, requireContext())
        binding.vaultsSearchViewer.setLayoutManager(LinearLayoutManager(binding.vaultsSearchViewer.context))
        binding.vaultsSearchViewer.setAdapter(_vaultAdapter)

        val root: View = binding.root
        return root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.searchView.clearFocus()
        binding.searchView.setOnQueryTextListener( object : SearchView.OnQueryTextListener,
            android.widget.SearchView.OnQueryTextListener {
            override fun onQueryTextSubmit(query: String?): Boolean {
                return false
            }

            override fun onQueryTextChange(newText: String?): Boolean {
                val newList: List<Vault> = _db!!.searchVaults(newText ?: "")
                _vaultAdapter!!.updateVaultList(newList)
                return true
            }
        })
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}