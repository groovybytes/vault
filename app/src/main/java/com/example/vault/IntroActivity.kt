package com.example.vault

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import android.content.Intent
import android.widget.Button
import android.widget.MediaController
import android.widget.VideoView

class IntroActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_intro)

        val videoView = findViewById<VideoView>(R.id.introVideoView)
        val getStartedButton = findViewById<Button>(R.id.getStartedButton)

        // Set up MediaController
        val mediaController = MediaController(this)
        mediaController.setAnchorView(videoView) // Attach the MediaController to the VideoView

        // Load and start video
        videoView.setVideoPath("android.resource://" + packageName + "/" + R.raw.intro_video)
        videoView.setMediaController(mediaController)

        // Auto-start the video
        videoView.setOnPreparedListener {
            videoView.start()
        }

        // Handle "Get Started" button
        getStartedButton.setOnClickListener {
            // Navigate to main activity and finish intro
            val sharedPreferences = getSharedPreferences("AppPrefs", MODE_PRIVATE)
            sharedPreferences.edit().putBoolean("isFirstRun", false).apply()

            // Navigate to main activity
            startActivity(Intent(this, MainActivity::class.java))
            finish()
        }
    }
}
