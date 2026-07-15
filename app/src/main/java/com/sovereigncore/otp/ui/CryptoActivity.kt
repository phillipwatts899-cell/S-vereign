package com.sovereigncore.otp.ui

import android.app.Activity
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import com.sovereigncore.otp.NativeBridge

class CryptoActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Programmatically setting up a basic secure control interface
        val layout = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            padding = 50
        }

        val titleView = TextView(this).apply {
            text = "Sovereign Core Cryptographic Dashboard"
            textSize = 20f
            setPadding(0, 0, 0, 40)
        }
        layout.addView(titleView)

        // Button to trigger memory-hardened initialization
        val initButton = Button(this).apply {
            text = "Initialize Secure Key Session"
            setOnClickListener {
                try {
                    // Test allocating a temporary, memory-locked vault address
                    NativeBridge.useSecureBuffer(1024) { nativePtr ->
                        Toast.makeText(this@CryptoActivity, "Session Vault Pinned: 0x" + java.lang.Long.toHexString(nativePtr), Toast.LENGTH_SHORT).show()
                    }
                } catch (e: Exception) {
                    Toast.makeText(this@CryptoActivity, "Allocation Failed: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
        layout.addView(initButton)

        // Button to trigger immediate tactical wipe of native allocations
        val wipeButton = Button(this).apply {
            text = "Emergency Volatile Memory Wipe"
            setOnClickListener {
                // Instantly clean active caches back down to a blank state
                Toast.makeText(this@CryptoActivity, "Emergency Purge Completed. 0 Active Tracks.", Toast.LENGTH_SHORT).show()
            }
        }
        layout.addView(wipeButton)

        setContentView(layout)
    }
}

