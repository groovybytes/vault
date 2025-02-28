package com.example.vault.ui.profile

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.lifecycle.ViewModelProvider
import com.example.vault.R
import com.example.vault.Session
import com.example.vault.databinding.FragmentProfileBinding
import com.google.android.gms.maps.CameraUpdateFactory
import com.google.android.gms.maps.GoogleMap
import com.google.android.gms.maps.OnMapReadyCallback
import com.google.android.gms.maps.SupportMapFragment
import com.google.android.gms.maps.model.LatLng
import com.google.android.gms.maps.model.MarkerOptions

class ProfileFragment : Fragment(), OnMapReadyCallback {

    private var _binding: FragmentProfileBinding? = null

    // This property is only valid between onCreateView and
    // onDestroyView.
    private val binding get() = _binding!!

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        val profileViewModel =
            ViewModelProvider(this)[ProfileViewModel::class.java]

        _binding = FragmentProfileBinding.inflate(inflater, container, false)
        val root: View = binding.root
        val mapFragment = childFragmentManager.findFragmentById(R.id.map) as? SupportMapFragment
        mapFragment?.getMapAsync(this)

        binding.githubText.setOnClickListener {
            Session.handleUserAuthentication(requireContext(), Session.AUTH_URL) { success, msg, userDetails ->
                // Display a toast message to the user
                if (msg != null) {
                    Log.println(if (success) Log.INFO else Log.ERROR, "ProfileFragment", msg)
                    Toast.makeText(requireContext(), msg, Toast.LENGTH_LONG).show()
                }

                if (success) {
                    // User is authenticated; proceed with the app
                    displayUserDetails(userDetails)
                }
            }
        }
        return root
    }

    fun displayUserDetails(userDetails: Map<String, String?>) {
//        val nameTextView = binding.root.findViewById<TextView>(R.id.name)
//        nameTextView.text = userDetails.token.name
    }

    override fun onMapReady(map: GoogleMap) {

        val university = LatLng(43.9456, -78.8968)
        map.addMarker(
            MarkerOptions()
                .position(university)
                .title("Ontario Tech University")
        )
        map.moveCamera(CameraUpdateFactory.newLatLngZoom(university, 15f))
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}