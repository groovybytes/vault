package com.example.vault.ui.home

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import com.example.vault.SecureKeyVault
import com.example.vault.db.VaultDatabase
import com.example.vault.VaultViewAdapter
import com.example.vault.databinding.FragmentHomeBinding

class HomeFragment : Fragment() {

    private var _binding: FragmentHomeBinding? = null
    private var _db: VaultDatabase? = null
    private var _vaultAdapter: VaultViewAdapter? = null
    private lateinit var keyVault: SecureKeyVault

    // This property is only valid between onCreateView and
    // onDestroyView.
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {

        _binding = FragmentHomeBinding.inflate(inflater, container, false)

        _db = VaultDatabase(activity, "vaultdb", null)

        keyVault = SecureKeyVault(requireContext(), this)
        keyVault.init {}

        _vaultAdapter = VaultViewAdapter(_db!!.getVaults(), keyVault)
        binding.vaultsHomeViewer.setLayoutManager(LinearLayoutManager(binding.vaultsHomeViewer.context))
        binding.vaultsHomeViewer.setAdapter(_vaultAdapter)

        val root: View = binding.root
        return root
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}