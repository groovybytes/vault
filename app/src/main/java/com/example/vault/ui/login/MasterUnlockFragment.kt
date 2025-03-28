package com.example.vault.ui.login

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.lifecycle.Observer
import androidx.lifecycle.ViewModelProvider
import androidx.annotation.StringRes
import androidx.fragment.app.Fragment
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.widget.Toast
import com.example.vault.databinding.FragmentMasterUnlockBinding

import com.example.vault.R
import com.example.vault.SecureKeyVault
import com.example.vault.db.VaultDatabase
import com.ionspin.kotlin.crypto.util.encodeToUByteArray
import java.nio.charset.Charset

class MasterUnlockFragment : Fragment() {

  private var _db: VaultDatabase? = null
  private lateinit var keyVault: SecureKeyVault
  private lateinit var loginViewModel: LoginViewModel
  private var _binding: FragmentMasterUnlockBinding? = null

  // This property is only valid between onCreateView and
  // onDestroyView.
  private val binding get() = _binding!!

  override fun onCreateView(
    inflater: LayoutInflater,
    container: ViewGroup?,
    savedInstanceState: Bundle?
  ): View? {
    _db = VaultDatabase(activity, "vaultdb", null)

    keyVault = SecureKeyVault(requireContext(), this)
    keyVault.init {}

    _binding = FragmentMasterUnlockBinding.inflate(inflater, container, false)
    return binding.root

  }

  @OptIn(ExperimentalUnsignedTypes::class)
  override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
    super.onViewCreated(view, savedInstanceState)
    loginViewModel = ViewModelProvider(this, LoginViewModelFactory())
      .get(LoginViewModel::class.java)

    val usernameEditText = binding.username
    val passwordEditText = binding.password
    val passwordUnlockButton = binding.passwordUnlock
    val biometricsUnlockButton = binding.biometicUnlock
    val loadingProgressBar = binding.loading

    loginViewModel.loginFormState.observe(
      viewLifecycleOwner,
      Observer { loginFormState ->
        if (loginFormState == null) {
          return@Observer
        }
        passwordUnlockButton.isEnabled = loginFormState.isDataValid
        loginFormState.usernameError?.let {
          usernameEditText.error = getString(it)
        }
        loginFormState.passwordError?.let {
          passwordEditText.error = getString(it)
        }
      })

    loginViewModel.loginResult.observe(
      viewLifecycleOwner,
      Observer { loginResult ->
        loginResult ?: return@Observer
        loadingProgressBar.visibility = View.GONE
        loginResult.error?.let {
          showLoginFailed(it)
        }
        loginResult.success?.let {
          updateUiWithUser(it)
        }
      })

    val afterTextChangedListener = object : TextWatcher {
      override fun beforeTextChanged(s: CharSequence, start: Int, count: Int, after: Int) {
        // ignore
      }

      override fun onTextChanged(s: CharSequence, start: Int, before: Int, count: Int) {
        // ignore
      }

      override fun afterTextChanged(s: Editable) {
        loginViewModel.loginDataChanged(
          usernameEditText.text.toString(),
          passwordEditText.text.toString()
        )
      }
    }
    usernameEditText.addTextChangedListener(afterTextChangedListener)
    passwordEditText.addTextChangedListener(afterTextChangedListener)
    passwordEditText.setOnEditorActionListener { _, actionId, _ ->
      if (actionId == EditorInfo.IME_ACTION_DONE) {
        loginViewModel.login(
          usernameEditText.text.toString(),
          passwordEditText.text.toString()
        )
      }
      false
    }

    passwordUnlockButton.setOnClickListener {
      // Generate a new master key from a password input.
      val password = passwordEditText.text.toString()
      val masterKey = if (password.startsWith("${SecureKeyVault.RECOVERY_KEY_PREFIX}-")) {
        SecureKeyVault.deriveKeyFromPassword(
          password = password,
          context = it.context
        )
      } else {
        SecureKeyVault.deriveKeyFromPassword(
          recoveryKey = password,
          context = it.context
        )
      }

      loadingProgressBar.visibility = View.VISIBLE
      loginViewModel.login(
        usernameEditText.text.toString(),
        masterKey.toString()
      )
    }

    biometricsUnlockButton.setOnClickListener {
      keyVault.init {
        keyVault.authenticate(
          masterKey = null,
          credential = null,
          onSuccess = { masterKey, recoveryKey ->
            if (recoveryKey != null) {
              val clipboard = requireContext()
                .getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
              val clip = ClipData.newPlainText("Recovery Key", recoveryKey)
              clipboard.setPrimaryClip(clip)
              Toast.makeText(
                requireContext(),
                "Recovery key copied to clipboard!",
                Toast.LENGTH_SHORT
              ).show()
            }

            val message = "Hello, world!".encodeToUByteArray()
            val (encryptedData, nonce) = keyVault.encryptData(message, masterKey)
            println("Encrypted data: $encryptedData")

            val decryptedData = keyVault.decryptData(encryptedData, nonce, masterKey)
            println("Decrypted data bytes: $decryptedData")
            println(
              "Decrypted data: ${
                String(
                  decryptedData.toByteArray(),
                  Charset.forName("UTF-8")
                )
              }"
            )

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

  private fun updateUiWithUser(model: LoggedInUserView) {
    val welcome = getString(R.string.welcome) + model.displayName
    // TODO : initiate successful logged in experience
    val appContext = context?.applicationContext ?: return
    Toast.makeText(appContext, welcome, Toast.LENGTH_LONG).show()
  }

  private fun showLoginFailed(@StringRes errorString: Int) {
    val appContext = context?.applicationContext ?: return
    Toast.makeText(appContext, errorString, Toast.LENGTH_LONG).show()
  }

  override fun onDestroyView() {
    super.onDestroyView()
    _binding = null
  }
}