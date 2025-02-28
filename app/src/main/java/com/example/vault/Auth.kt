package com.example.vault

import android.content.Context
import android.net.Uri
import android.util.Base64
import androidx.browser.customtabs.CustomTabsIntent
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import org.json.JSONException
import org.json.JSONObject
import retrofit2.Call
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.GET
import retrofit2.http.Header
import java.io.IOException

data class UserDetailsResponse(
    val token: Token
)

data class Token(
    val name: String?,
    val email: String?,
    val picture: String?,
    val sub: String?,
    val userId: String?,
    val bio: String?,
    val image: String?,
    val license: String?,
    val access_token: String?,
    val iat: Long?,
    val exp: Long?,
    val jti: String?
)

class Session {

    companion object {

        const val BASE_URL = "https://vault-cloud.vercel.app"
        const val SESSION_URL = "$BASE_URL/api/auth/session"
        const val AUTH_URL = "$BASE_URL/login"

        const val USER_DETAILS_PATH = "api/auth/token"

        private class ApiService(private val sessionToken: String) {
            private val retrofit = Retrofit.Builder()
                .baseUrl("$BASE_URL/")
                .addConverterFactory(GsonConverterFactory.create())
                .build()

            private val api = retrofit.create(Api::class.java)

            fun getUserDetails(): Call<UserDetailsResponse> {
                return api.getUserDetails("Bearer $sessionToken")
            }
        }

        private interface Api {
            @GET(USER_DETAILS_PATH)
            fun getUserDetails(@Header("Authorization") authHeader: String): Call<UserDetailsResponse>
        }

        // Handles the entire user authentication process,
        // including re-authentication, session validation, user details fetching,
        // launching the browser for login, etc.
        fun handleUserAuthentication(
            context: Context,
            authUrl: String,
            callback: (Boolean, String?, Map<String, String?>) -> Unit // Callback to notify success, with a message
        ) {
            // Check if user details exist in SharedPreferences
            val savedDetails = getUserDetails(context)
            val sessionToken = getSessionToken(context)

            // Check if the token is expired
            val exp = savedDetails["exp"]?.toLongOrNull()
            if (exp != null && isTokenExpired(exp)) {
                reauthenticate(context, authUrl, callback) // Token expired
                return
            }

            // Check if the user details are saved and the session token is valid
            if (!savedDetails["name"].isNullOrEmpty() && !sessionToken.isNullOrEmpty()) {
                // Validate the saved session token
                validateSessionToken(context, sessionToken) { isValid ->
                    if (isValid) {
                        callback(true, "User authenticated successfully.", savedDetails)
                    } else {
                        // Session expired or invalid, re-authenticate
                        reauthenticate(context, authUrl, callback)
                    }
                }
            } else {
                // No user details, re-authenticate
                reauthenticate(context, authUrl, callback)
            }
        }

        private fun reauthenticate(
            context: Context,
            authUrl: String,
            callback: (Boolean, String?, Map<String, String?>) -> Unit
        ) {
            // Launch login process
            launchLogin(context, authUrl)

            // Fetch session token after login
            fetchSessionToken { sessionToken ->
                if (sessionToken != null) {
                    // Save session token
                    saveSessionToken(context, sessionToken)

                    // Fetch user details
                    fetchUserDetails(context, sessionToken) { userDetails ->
                        if (userDetails != null) {
                            // Save and display user details
                            saveUserDetails(context, userDetails)

                            // Get the saved user details
                            val savedUserDetails = getUserDetails(context)
                            callback(true, "Re-authentication successful.", savedUserDetails)
                        } else {
                            callback(false, "Failed to fetch user details after re-authentication.", mapOf())
                        }
                    }
                } else {
                    callback(false, "Failed to retrieve session token during re-authentication.", mapOf())
                }
            }
        }

        private fun validateSessionToken(
            context: Context,
            sessionToken: String,
            callback: (Boolean) -> Unit
        ) {
            // Call a backend endpoint to validate the token
            fetchUserDetails(context, sessionToken) { userDetails ->
                if (userDetails != null) {
                    // Save the updated user details if valid
                    saveUserDetails(context, userDetails)
                    callback(true)
                } else {
                    // Token is invalid or expired
                    callback(false)
                }
            }
        }

        private fun fetchUserDetails(context: Context, sessionToken: String, callback: (UserDetailsResponse?) -> Unit) {
            val apiService = ApiService(sessionToken)
            apiService.getUserDetails().enqueue(object : retrofit2.Callback<UserDetailsResponse> {
                override fun onResponse(call: Call<UserDetailsResponse>, response: retrofit2.Response<UserDetailsResponse>) {
                    if (response.isSuccessful) {
                        val userDetails = response.body()
                        if (userDetails != null) {
                            saveUserDetails(context, userDetails)
                        }
                        callback(userDetails)
                    } else {
                        callback(null)
                    }
                }

                override fun onFailure(call: Call<UserDetailsResponse>, t: Throwable) {
                    callback(null)
                }
            })
        }

        private fun saveUserDetails(context: Context, userDetails: UserDetailsResponse) {
            val sharedPreferences = context.getSharedPreferences("auth", Context.MODE_PRIVATE)
            sharedPreferences.edit().apply {
                putString("name", userDetails.token.name)
                putString("email", userDetails.token.email)
                putString("picture", userDetails.token.picture)
                putString("access_token", userDetails.token.access_token)
                putString("license", userDetails.token.license)
                putInt("iat", userDetails.token.iat?.toInt() ?: 0)
                putInt("exp", userDetails.token.exp?.toInt() ?: 0)
                apply()
            }
        }

        private fun getUserDetails(context: Context): Map<String, String?> {
            val sharedPreferences = context.getSharedPreferences("auth", Context.MODE_PRIVATE)
            return mapOf(
                "name" to sharedPreferences.getString("name", null),
                "email" to sharedPreferences.getString("email", null),
                "picture" to sharedPreferences.getString("picture", null),
                "access_token" to sharedPreferences.getString("access_token", null),
                "license" to sharedPreferences.getString("license", null),
                "iat" to sharedPreferences.getInt("iat", 0).toString(),
                "exp" to sharedPreferences.getInt("exp", 0).toString()
            )
        }

        private fun fetchSessionToken(callback: (String?) -> Unit) {
            val url = AUTH_URL
            val cookieManager = android.webkit.CookieManager.getInstance()
            val cookies = cookieManager.getCookie(url) // Retrieves cookies for the domain

            val client = OkHttpClient.Builder()
                .addInterceptor { chain ->
                    val request = chain.request().newBuilder()
                        .addHeader("Cookie", cookies ?: "") // Add cookies to the request
                        .build()
                    chain.proceed(request)
                }
                .build()

            val request = Request.Builder()
                .url(url)
                .build()

            client.newCall(request).enqueue(object : okhttp3.Callback {
                override fun onResponse(call: okhttp3.Call, response: Response) {
                    if (response.isSuccessful) {
                        val responseBody = response.body?.string()
                        val sessionToken = parseSessionToken(responseBody)
                        callback(sessionToken)
                    } else {
                        callback(null)
                    }
                }

                override fun onFailure(call: okhttp3.Call, e: IOException) {
                    callback(null)
                }
            })
        }

        private fun parseSessionToken(responseBody: String?): String? {
            // Assuming responseBody contains JSON with the token
            // Example: { "token": "your_session_token" }
            return try {
                val json = JSONObject(responseBody ?: "")
                json.optString("token", null)
            } catch (e: JSONException) {
                null
            }
        }

        private fun saveSessionToken(context: Context, token: String) {
            // This isn't actually secure, but it's better than storing the token in plain text
            val encryptedToken = Base64.encodeToString(token.toByteArray(), Base64.DEFAULT)
            val sharedPreferences = context.getSharedPreferences("auth", Context.MODE_PRIVATE)
            sharedPreferences.edit().putString("session_token", encryptedToken).apply()
        }

        private fun getSessionToken(context: Context): String? {
            val sharedPreferences = context.getSharedPreferences("auth", Context.MODE_PRIVATE)

            // Short-circuit if the token is not found
            val encryptedToken = sharedPreferences.getString("session_token", null) ?: return null
            return String(Base64.decode(encryptedToken, Base64.DEFAULT))
        }

        private fun isTokenExpired(exp: Long?): Boolean {
            val currentTime = System.currentTimeMillis() / 1000
            return exp == null || currentTime >= exp
        }

        private fun launchLogin(context: Context, authUrl: String) {
            val builder = CustomTabsIntent.Builder()
            val customTabsIntent = builder.build()
            customTabsIntent.launchUrl(context, Uri.parse(authUrl))
        }

        fun clearCookies() {
            val cookieManager = android.webkit.CookieManager.getInstance()
            cookieManager.removeAllCookies(null)
            cookieManager.flush()
        }

    }

}