package au.com.unison.meshagent.ttm

import android.os.Bundle
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.webkit.*
import androidx.navigation.fragment.findNavController

/**
 * A simple [Fragment] subclass for displaying web content. * create an instance of this fragment.
 */
class WebViewFragment : Fragment() {
    var browser : WebView? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Listen for results from MainActivity
        parentFragmentManager.setFragmentResultListener(
            // Use the same request key defined in MainActivity
            MainActivity.WEBVIEW_FRAGMENT_REQUEST_KEY,
            this // LifecycleOwner
        ) { requestKey, bundle ->
            when (bundle.getString("action")) {
                MainActivity.ACTION_NAVIGATE -> {
                    bundle.getString(MainActivity.BUNDLE_URL_KEY)?.let { urlToLoad ->
                        navigate(urlToLoad)
                    }
                }
                MainActivity.ACTION_EXIT -> {
                    exit()
                }
            }
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.webview_fragment, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        // visibleScreen is a global in MainActivity.kt.
        // This is part of the older pattern.
        visibleScreen = 3

        browser = view.findViewById(R.id.mainWebView)
        browser?.settings?.javaScriptEnabled = true
        browser?.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(
                view: WebView?,
                url: String?
            ): Boolean {
                // pageUrl is a global in MainActivity.kt.
                // This is also part of the older pattern.
                // WebViewFragment should ideally manage its own current URL if needed,
                // or receive it via arguments/ViewModel.
                pageUrl = url
                url?.let { view?.loadUrl(it) }
                return true
            }
        }
        // pageUrl is global. Consider passing the initial URL via navigation arguments
        // when WebViewFragment is first created.
        pageUrl?.let { browser?.loadUrl(it) }
    }

    override fun onDestroyView() {
        browser?.let {
            it.stopLoading()
            it.clearHistory()
            it.clearCache(true)
            it.onPause()
            it.removeAllViews()
            (it.parent as? ViewGroup)?.removeView(it) // Good practice to remove from parent
            it.destroy()
        }
        browser = null
        super.onDestroyView()
    }

    fun navigate(url: String) {
        browser?.loadUrl(url)
    }

    fun exit() {
        browser?.stopLoading()
        browser?.loadUrl("about:blank")

        //pageUrl = null
        findNavController().navigate(R.id.action_webViewFragment_to_FirstFragment)
    }
}