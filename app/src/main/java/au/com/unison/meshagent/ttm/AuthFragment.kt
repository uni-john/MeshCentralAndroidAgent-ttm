package au.com.unison.meshagent.ttm

import android.os.Bundle
import android.os.CountDownTimer
import android.util.Base64
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import androidx.navigation.fragment.findNavController
import java.lang.Exception

class AuthFragment : Fragment() {
    var countDownTimer : CountDownTimer? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        println("onCreate-auth")
        super.onCreate(savedInstanceState)
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        println("onCreateView-auth")
        // Inflate the layout for this fragment
        return inflater.inflate(R.layout.fragment_auth, container, false)
    }

    override fun onDestroyView() {
        super.onDestroyView()
        countDownTimer?.cancel() // Ensure the timer is stopped
        countDownTimer = null
        authFragment = null
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        println("onViewCreated-auth")
        super.onViewCreated(view, savedInstanceState)
        authFragment = this
        visibleScreen = 4

        // Set authentication code
        val t:TextView = view.findViewById<Button>(R.id.authTopText2) as TextView
        t.text = getString(R.string.default_auth_code)
        if (g_auth_url != null) {
            val authCode: String? = g_auth_url?.getQueryParameter("code")
            if (authCode != null) {
                t.text = String(Base64.decode(authCode, Base64.DEFAULT), charset("UTF-8"))
            }
        }

        // Set authentication progress bar
        val p: ProgressBar = view.findViewById(R.id.authProgressBar)
        p.progress = 100
        countDownTimer = object : CountDownTimer(60000, 600) {
            override fun onTick(millisUntilFinished: Long) {
                val progressBarTick: ProgressBar? = view.findViewById(R.id.authProgressBar)
                if (progressBarTick != null && progressBarTick.progress > 0) {
                    progressBarTick.progress = progressBarTick.progress - 1
                }
            }
            override fun onFinish() {
                countDownTimer = null
                exit()
            }
        }.start()

        view.findViewById<Button>(R.id.authAcceptButton).setOnClickListener {
            if ((meshAgent != null) && (g_auth_url != null)) { meshAgent?.send2faAuth(g_auth_url!!, true) }
            g_auth_url = null
            exit()
        }

        view.findViewById<Button>(R.id.authRejectButton).setOnClickListener {
            if ((meshAgent != null) && (g_auth_url != null)) { meshAgent?.send2faAuth(g_auth_url!!, false) }
            g_auth_url = null
            exit()
        }
    }

    fun exit() {
        if (countDownTimer != null) {
            countDownTimer?.cancel()
            countDownTimer = null
        }
        try {
            findNavController().navigate(R.id.action_authFragment_to_FirstFragment)
        } catch (ex: Exception) {
            android.util.Log.e("AuthFragment", "Error during navigation in exit()", ex)
        }
    }
}