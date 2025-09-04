package au.com.unison.meshagent.ttm

import android.app.RecoverableSecurityException
import android.content.ContentResolver
import android.content.ContentUris
import android.content.ContentValues
//import android.database.Cursor
import android.net.Uri
import android.os.Build
import android.os.CountDownTimer
import android.os.Environment
import android.provider.MediaStore
import android.util.Base64
import okhttp3.*
import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.json.JSONArray
import org.json.JSONObject
//import org.webrtc.PeerConnectionFactory
import java.io.*
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
//import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.collections.ArrayList
import kotlin.math.absoluteValue
import kotlin.random.Random


class PendingActivityData(
    var tunnel: MeshTunnel,
    var id: Int,
    var url: Uri,
    var where: String,
    var args: String,
    var req: JSONObject) {
}

class MeshTunnel(
    var parent: MeshAgent,
    var url: String,
    var serverData: JSONObject) : WebSocketListener() {
    //private var parent : MeshAgent = parent
    //private var url:String = url
    //private var serverData: JSONObject = serverData
    private var serverTlsCertHash: ByteArray? = null
    private var connectionTimer: CountDownTimer? = null
    var _webSocket: WebSocket? = null
    var state: Int = 0 // 0 = Disconnected, 1 = Connecting, 2 = Connected
    var usage: Int = 0 // 2 = Desktop, 5 = Files, 10 = File transfer
    private var tunnelOptions : JSONObject? = null
    private var lastDirRequest : JSONObject? = null
    private var fileUpload : OutputStream? = null
    private var fileUploadName : String? = null
    private var fileUploadReqId : Int = 0
    private var fileUploadSize : Int = 0
    var userid : String? = null
    var guestname : String? = null
    var sessionUserName : String? = null // UserID + GuestName in Base64 if this is a shared session.
    var sessionUserName2 : String? = null // UserID/GuestName

    init { }

    fun Start() {
        //println("MeshTunnel Init: ${serverData.toString()}")
        val serverTlsCertHashHex = serverData.optString("servertlshash")
        serverTlsCertHash = parent.hexToByteArray(serverTlsCertHashHex)
        //var tunnelUsage = serverData.getInt("usage")
        //var tunnelUser = serverData.getString("username")

        // Set the userid and request more data about this user
        guestname = serverData.optString("guestname")
        userid = serverData.optString("userid")
        if (userid != null) parent.sendUserImageRequest(userid!!)
        sessionUserName = userid
        sessionUserName2 = userid
        if ((userid != "") && (guestname != "")) {
            sessionUserName = userid + "/guest:" + Base64.encodeToString(guestname!!.toByteArray(), Base64.NO_WRAP)
            sessionUserName2 = "$userid/$guestname"
        }

        //println("Starting tunnel: $url")
        //println("Tunnel usage: $tunnelUsage")
        //println("Tunnel user: $tunnelUser")
        //println("Tunnel userid: $userid")
        //println("Tunnel sessionUserName: $sessionUserName")
        //println("Tunnel sessionUserName2: $sessionUserName2")
        startSocket()
    }

    fun Stop() {
        //println("MeshTunnel Stop")
        stopSocket()
    }

    private fun getUnsafeOkHttpClient(): OkHttpClient {
        // Create a trust manager that does not validate certificate chains
        val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(
                    chain: Array<out X509Certificate>?,
                    authType: String?
            ) {
            }

            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                val firstCertificateEncoded: ByteArray? = chain?.firstOrNull()?.encoded

                if (firstCertificateEncoded != null) {
                    // Now 'firstCertificateEncoded' is confirmed non-null here
                    val calculatedHash = MessageDigest.getInstance("SHA-384").digest(firstCertificateEncoded).toHex()

                    // Check against the tunnel's specific serverTlsCertHash (if set)
                    val currentTunnelCertHash = serverTlsCertHash // Local val for smart casting
                    if (currentTunnelCertHash != null && calculatedHash == currentTunnelCertHash.toHex()) {
                        return
                    }

                    // Check against the parent agent's serverTlsCertHash (if set)
                    val parentCertHash = parent.serverTlsCertHash // Local val for smart casting
                    if (parentCertHash != null && calculatedHash == parentCertHash.toHex()) {
                        return
                    }

                    println("Got Bad Tunnel TlsHash: $calculatedHash. Expected tunnel: ${currentTunnelCertHash?.toHex()}, Expected parent: ${parentCertHash?.toHex()}")
                    throw CertificateException("Server certificate hash mismatch.")
                } else {
                    // This case is critical: No valid certificate was found in the chain to hash.
                    // This should be treated as a failure in trust verification.
                    println("Error: Could not get encoded certificate from the server's chain in checkServerTrusted.")
                    throw CertificateException("Server certificate chain is invalid or empty.")
                }
            }

            override fun getAcceptedIssuers() = arrayOf<X509Certificate>()
        })

        // Install the special trust manager that records the certificate hash of the server
        val sslContext = SSLContext.getInstance("SSL")
        sslContext.init(null, trustAllCerts, java.security.SecureRandom())
        val sslSocketFactory = sslContext.socketFactory

        return OkHttpClient.Builder()
                .connectTimeout(20, TimeUnit.SECONDS)
                .readTimeout(60, TimeUnit.MINUTES)
                .writeTimeout(60, TimeUnit.MINUTES)
                .hostnameVerifier { _, _ -> true }
                .sslSocketFactory(sslSocketFactory, trustAllCerts[0] as X509TrustManager)
                .build()
    }

    fun startSocket() {
        _webSocket = getUnsafeOkHttpClient().newWebSocket(
                Request.Builder().url(url).build(),
                this
        )
    }

    fun stopSocket() {
        // Disconnect and clean the relay socket
        if (_webSocket != null) {
            try {
                _webSocket?.close(NORMAL_CLOSURE_STATUS, null)
            } catch (e: Exception) {
                println("MeshTunnel: Error closing WebSocket: ${e.message}")
            } finally {
                _webSocket = null
            }
        }
        // Clear the connection timer
        if (connectionTimer != null) {
            connectionTimer?.cancel()
            connectionTimer = null
        }
        // Remove the tunnel from the parent's list
        parent.removeTunnel(this) // Notify the parent that this tunnel is done

        // Check if there are no more remote desktop tunnels
        if ((usage == 2) && (g_ScreenCaptureService != null)) {
            g_ScreenCaptureService!!.checkNoMoreDesktopTunnels()
        }
    }

    fun sendCtrlResponse(values: JSONObject?) {
        val json = JSONObject()
        json.put("ctrlChannel", "102938")
        values?.let {
            for (key in it.keys()) {
                json.put(key, it.get(key))
            }
        }
        if (_webSocket != null) { _webSocket?.send(json.toString()) }
    }

    companion object {
        const val NORMAL_CLOSURE_STATUS = 1000
    }

    override fun onOpen(webSocket: WebSocket, response: Response) {
        //println("Tunnel-onOpen")
    }

    override fun onMessage(webSocket: WebSocket, text: String) {
        //println("Tunnel-onMessage: $text")
        if (state == 0) {
            if ((text == "c") || (text == "cr")) { state = 1; }
            return
        }
        else if (state == 1) {
            // {"type":"options","file":"Images/1104105516.JPG"}
            if (text.startsWith('{')) {
                val json = JSONObject(text)
                val type = json.optString("type")
                if (type == "options") { tunnelOptions = json }
            } else {
                val xusage = text.toInt()
                if (((xusage < 1) || (xusage > 5)) && (xusage != 10)) {
                    println("Invalid usage $text"); stopSocket(); return
                }
                // Disabled as unused
                // val serverExpectedUsage = serverData.optInt("usage") // optInt returns 0 if not found, not null

                // optInt returns the value if found, or a default value (0 for optInt if key missing).
                if (serverData.has("usage")) {
                    val expectedUsage = serverData.getInt("usage") // Use getInt if you know it exists
                    if (expectedUsage != xusage) {
                        println("Unexpected usage $xusage != $expectedUsage (server expected)")
                        stopSocket()
                        return
                    }
                }

                usage = xusage // 2 = Desktop, 5 = Files, 10 = File transfer
                state = 2

                // Start the connection time except if this is a file transfer
                if (usage != 10) {
                    //println("Connected usage $usage")
                    startConnectionTimer()
                    if (usage == 2) {
                        // If this is a remote desktop usage...
                        if (!g_autoConsent && g_ScreenCaptureService == null) {
                            // asking for consent
                            if (meshAgent?.tunnels?.getOrNull(0) != null) {
                                val json = JSONObject()
                                json.put("type", "console")
                                json.put("msg", "Waiting for user to grant access...")
                                json.put("msgid", 1)
                                meshAgent!!.tunnels[0].sendCtrlResponse(json)
                            }
                        }
                        if (g_ScreenCaptureService == null) {
                            // Request media projection
                            parent.parent.startProjection()
                        } else {
                            if (meshAgent?.tunnels?.getOrNull(0) != null) {
                                val json = JSONObject()
                                json.put("type", "console")
                                json.put("msg", null)
                                json.put("msgid", 0)
                                meshAgent!!.tunnels[0].sendCtrlResponse(json)
                            }
                            // Send the display size
                            updateDesktopDisplaySize()
                        }
                    }
                } else {
                    // This is a file transfer
                    if (tunnelOptions == null) {
                        println("No file transfer options")
                        stopSocket()
                    } else {
                        val filename = tunnelOptions?.optString("file")
                        if (filename == null) {
                            println("No file transfer name")
                            stopSocket()
                        } else {
                            //println("File transfer usage")
                            startFileTransfer(filename)
                        }
                    }
                }
            }
        }
    }

    // Change 'msg' to 'bytes' to match the supertype
    override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
        //println("Tunnel-onBinaryMessage: ${bytes.size}, ${bytes.toByteArray().toHex()}")
        if ((state != 2) || (bytes.size < 2)) return
        try {
            if (bytes[0].toInt() == 123) {
                // If we are authenticated, process JSON data
                processTunnelData(String(bytes.toByteArray(), Charsets.UTF_8))
            } else if (fileUpload != null) {
                // If this is file upload data, process it here
                if (bytes[0].toInt() == 0) {
                    // If data starts with zero, skip the first byte. This is used to escape binary file data from JSON.
                    fileUploadSize += (bytes.size - 1)
                    val buf = bytes.toByteArray() // Renamed to 'buf' for clarity if you prefer, or keep using 'bytes'
                    try {
                        fileUpload?.write(buf, 1, buf.size - 1)
                    } catch (e : Exception) {
                        // Report a problem
                        println("MeshTunnel: Error writing to fileUpload: ${e.message}")
                        uploadError()
                        return
                    }
                } else {
                    // If data does not start with zero, save as-is.
                    fileUploadSize += bytes.size
                    try {
                        fileUpload?.write(bytes.toByteArray())
                    } catch (e : Exception) {
                        // Report a problem
                        println("MeshTunnel: Error writing raw data to fileUpload: ${e.message}")
                        uploadError()
                        return
                    }
                }

                // Ask for more data
                val json = JSONObject()
                json.put("action", "uploadack")
                json.put("reqid", fileUploadReqId)
                if (_webSocket != null) { _webSocket?.send(json.toString().toByteArray().toByteString()) }
            } else {
                if (bytes.size < 2) return // Use 'bytes' here
                val cmd : Int = (bytes[0].toInt() shl 8) + bytes[1].toInt()
                val cmdsize : Int = (bytes[2].toInt() shl 8) + bytes[3].toInt()
                if (cmdsize != bytes.size) return // Use 'bytes' here
                //println("Cmd $cmd, Size: ${bytes.size}, Hex: ${bytes.toByteArray().toHex()}")
                if (usage == 2) processBinaryDesktopCmd(cmd, cmdsize, bytes) // Remote desktop
            }
        }
        catch (e: Exception) {
            println("Tunnel-Exception: ${e.toString()}")
        }
    }

    private fun processBinaryDesktopCmd(cmd : Int, cmdsize: Int, msg: ByteString) {
        when (cmd) {
            1 -> { // Legacy key input
                // Nop
            }
            2 -> { // Mouse input
                // Nop
            }
            5 -> { // Remote Desktop Settings
                if (cmdsize < 6) return
                g_desktop_imageType = msg[4].toInt() // 1 = JPEG, 2 = PNG, 3 = TIFF, 4 = WebP. TIFF is not support on Android.
                g_desktop_compressionLevel = msg[5].toInt() // Value from 1 to 100
                if (cmdsize >= 8) { g_desktop_scalingLevel = (msg[6].toInt() shl 8).absoluteValue + msg[7].toInt().absoluteValue } // 1024 = 100%
                if (cmdsize >= 10) { g_desktop_frameRateLimiter = (msg[8].toInt() shl 8).absoluteValue + msg[9].toInt().absoluteValue }
                println("Desktop Settings, type=$g_desktop_imageType, comp=$g_desktop_compressionLevel, scale=$g_desktop_scalingLevel, rate=$g_desktop_frameRateLimiter")
                updateDesktopDisplaySize()
            }
            6 -> { // Refresh
                // Nop
                println("Desktop Refresh")
            }
            8 -> { // Pause
                // Nop
            }
            85 -> { // Unicode key input
                // Nop
            }
            87 -> { // Input Lock
                // Nop
            }
            else -> {
                println("Unknown desktop binary command: $cmd, Size: ${msg.size}, Hex: ${msg.toByteArray().toHex()}")
            }
        }
    }

    fun updateDesktopDisplaySize() {
        if ((g_ScreenCaptureService == null) || (_webSocket == null)) return
        //println("updateDesktopDisplaySize: ${g_ScreenCaptureService!!.mWidth} x ${g_ScreenCaptureService!!.mHeight}")

        // Get the display size
        var mWidth : Int = g_ScreenCaptureService!!.mWidth
        var mHeight : Int = g_ScreenCaptureService!!.mHeight

        // Scale the display if needed
        if (g_desktop_scalingLevel != 1024) {
            mWidth = (mWidth * g_desktop_scalingLevel) / 1024
            mHeight = (mHeight * g_desktop_scalingLevel) / 1024
        }

        // Send the display size command
        val bytesOut = ByteArrayOutputStream()
        DataOutputStream(bytesOut).use { dos ->
            with(dos) {
                writeShort(7) // Screen size command
                writeShort(8) // Screen size command size
                writeShort(mWidth) // Width
                writeShort(mHeight) // Height
            }
        }
        _webSocket!!.send(bytesOut.toByteArray().toByteString())
    }

    // Cause some data to be sent over the websocket control channel every 2 minutes to keep it open
    private fun startConnectionTimer() {
        parent.parent.runOnUiThread {
            connectionTimer = object: CountDownTimer(120000000, 120000) {
                override fun onTick(millisUntilFinished: Long) {
                    if (_webSocket != null) {
                        _webSocket?.send(ByteArray(1).toByteString()) // If not, sent a single zero byte
                    }
                }
                override fun onFinish() { startConnectionTimer() }
            }
            connectionTimer?.start()
        }
    }

    private fun uploadError() {
        val json = JSONObject()
        json.put("action", "uploaderror")
        json.put("reqid", fileUploadReqId)
        if (_webSocket != null) { _webSocket?.send(json.toString().toByteArray().toByteString()) }
        try { fileUpload?.close() } catch (closeException : Exception) {
            // Log that an error occurred during file close, especially after an upload error
            println("MeshTunnel: Error closing fileUpload after upload error: ${closeException.message}")
            // android.util.Log.w("MeshTunnel", "Error closing fileUpload in uploadError()", closeException)
        }
        fileUpload = null
        return
    }

    private fun processTunnelData(jsonStr: String) {
        //println("JSON: $jsonStr")
        val json = JSONObject(jsonStr)
        val action = json.getString("action")
        //println("action: $action")
        when (action) {
            "ls" -> {
                val path = json.getString("path")
                if (path == "") {
                    val r = JSONArray()
                    r.put(JSONObject("{n:\"Sdcard\",t:2}"))
                    r.put(JSONObject("{n:\"Images\",t:2}"))
                    r.put(JSONObject("{n:\"Audio\",t:2}"))
                    r.put(JSONObject("{n:\"Videos\",t:2}"))
                    //r.put(JSONObject("{n:\"Documents\",t:2}"))
                    json.put("dir", r)
                } else {
                    lastDirRequest = json // Bit of a hack, but use this to refresh after a file delete
                    json.put("dir", getFolder(path))
                }
                if (_webSocket != null) {
                    _webSocket?.send(json.toString().toByteArray(Charsets.UTF_8).toByteString())
                }
            }
            "rm" -> {
                val path = json.getString("path")
                val filenames = json.getJSONArray("delfiles")
                deleteFile(path, filenames, json)
            }
            "upload" -> {
                // {"action":"upload","reqid":0,"path":"Images","name":"00000000.JPG","size":1180231}
                val path = json.getString("path")
                val name = json.getString("name")
                //val size = json.getInt("size")
                val reqid = json.getInt("reqid")

                // Close previous upload
                if (fileUpload != null) {
                    fileUpload?.close()
                    fileUpload = null
                }

                // Setup
                fileUploadName = name
                fileUploadReqId = reqid
                fileUploadSize = 0

                if (path.startsWith("Sdcard")) {
                    val fileDir: String = path.replaceFirst("Sdcard", Environment.getExternalStorageDirectory().absolutePath)
                    val file = File(fileDir, name)
                    try {
                        fileUpload = FileOutputStream(file)
                    } catch (fileCreationException: Exception) {
                        // Log the specific exception that occurred during FileOutputStream creation
                        println("MeshTunnel: Failed to create FileOutputStream for $name in $fileDir. Error: ${fileCreationException.message}")
                        // android.util.Log.e("MeshTunnel", "Failed to create FileOutputStream for $name in $fileDir", fileCreationException)
                        uploadError() // Notifies client and attempts cleanup
                        return
                    }
                } else {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        val resolver: ContentResolver = parent.parent.getContentResolver()
                        val contentValues = ContentValues()
                        var fileUri: Uri? = null
                        contentValues.put(MediaStore.MediaColumns.DISPLAY_NAME, name)
                        val (mimeType, relativePath, externalUri) = when {
                            name.lowercase().endsWith(".jpg") || name.lowercase().endsWith(".jpeg") -> Triple("image/jpg", Environment.DIRECTORY_PICTURES, MediaStore.Images.Media.EXTERNAL_CONTENT_URI)
                            name.lowercase().endsWith(".png") -> Triple("image/png", Environment.DIRECTORY_PICTURES, MediaStore.Images.Media.EXTERNAL_CONTENT_URI)
                            name.lowercase().endsWith(".bmp") -> Triple("image/bmp", Environment.DIRECTORY_PICTURES, MediaStore.Images.Media.EXTERNAL_CONTENT_URI)
                            name.lowercase().endsWith(".mp4") -> Triple("video/mp4", Environment.DIRECTORY_MOVIES, MediaStore.Video.Media.EXTERNAL_CONTENT_URI)
                            name.lowercase().endsWith(".mp3") -> Triple("audio/mpeg3", Environment.DIRECTORY_MUSIC, MediaStore.Audio.Media.EXTERNAL_CONTENT_URI)
                            name.lowercase().endsWith(".ogg") -> Triple("audio/ogg", Environment.DIRECTORY_MUSIC, MediaStore.Audio.Media.EXTERNAL_CONTENT_URI)
                            else -> {
                                println("Unsupported file type: $name")
                                Triple(null, null, null)
                            }
                        }
                        if (mimeType != null && relativePath != null && externalUri != null) {
                            contentValues.put(MediaStore.MediaColumns.MIME_TYPE, mimeType)
                            contentValues.put(MediaStore.MediaColumns.RELATIVE_PATH, relativePath)
                            fileUri = resolver.insert(externalUri, contentValues)

                            if (fileUri != null) { // Safely check if URI is not null
                                try {
                                    fileUpload = resolver.openOutputStream(fileUri) // No need for '!!' now
                                } catch (outputStreamException: Exception) { // Renamed and will be used
                                    println("MeshTunnel: Error opening OutputStream for URI $fileUri. Error: ${outputStreamException.message}")
                                    // android.util.Log.e("MeshTunnel", "Error opening OutputStream for URI $fileUri", outputStreamException)
                                    uploadError()
                                    return
                                }
                            } else {
                                // Handle the case where resolver.insert() returned a null URI
                                println("MeshTunnel: Failed to insert media content, URI is null for $name.")
                                // android.util.Log.e("MeshTunnel", "Failed to insert media content, URI is null for $name.")
                                uploadError()
                                return
                            }
                        } else {
                            // This 'else' implies mimeType, relativePath, or externalUri was null from the 'when' expression
                            println("MeshTunnel: Cannot upload. MimeType, relativePath, or externalUri is null for file type of $name.")
                            uploadError()
                            return
                        }
                    } else {
                        val fileExtension = name.lowercase().substringAfterLast('.')
                        val fileDir: String = when (fileExtension) {
                            "jpg", "jpeg", "png" -> Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES).toString()
                            "mp4", "mkv" -> Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_MOVIES).toString()
                            "mp3", "wav" -> Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_MUSIC).toString()
                            else -> Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS).toString()
                        }
                        val file = File(fileDir, name)
                        try {
                            fileUpload = FileOutputStream(file)
                        } catch (fileCreationException: Exception) { // Renamed and will be used
                            // Log the specific exception that occurred
                            println("MeshTunnel: Failed to create FileOutputStream (pre-Q) for $name in $fileDir. Error: ${fileCreationException.message}")
                            // For more detailed logging in Android:
                            // android.util.Log.e("MeshTunnel", "Failed to create FileOutputStream (pre-Q) for $name in $fileDir", fileCreationException)

                            uploadError() // Notifies client and attempts cleanup
                            return
                        }
                    }
                }

                // Send response
                val json = JSONObject()
                json.put("action", "uploadstart")
                json.put("reqid", reqid)
                if (_webSocket != null) { _webSocket?.send(json.toString().toByteArray().toByteString()) }
            }
            "uploaddone" -> {
                if (fileUpload == null) return
                fileUpload?.close()
                fileUpload = null

                // Send response
                val json = JSONObject()
                json.put("action", "uploaddone")
                json.put("reqid", fileUploadReqId)
                if (_webSocket != null) { _webSocket?.send(json.toString().toByteArray().toByteString()) }

                // Event the server
                val eventArgs = JSONArray()
                eventArgs.put(fileUploadName)
                eventArgs.put(fileUploadSize)
                parent.logServerEventEx(105, eventArgs, "Upload: \"${fileUploadName}}\", Size: $fileUploadSize", serverData)
            }
            else -> {
                // Unknown command, ignore it.
                println("Unhandled action: $action, $jsonStr")
            }
        }
    }

    // https://developer.android.com/training/data-storage/shared/media
    fun getFolder(dir: String) : JSONArray {
        val r = JSONArray()
        val projection = arrayOf(
                MediaStore.MediaColumns.DISPLAY_NAME,
                MediaStore.MediaColumns.DATE_MODIFIED,
                MediaStore.MediaColumns.SIZE,
                MediaStore.MediaColumns.MIME_TYPE
        )
        var uri : Uri? = null
        if (dir.startsWith("Sdcard")) { uri = Uri.fromFile(Environment.getExternalStorageDirectory()) }
        if (dir == "Images") { uri = MediaStore.Images.Media.EXTERNAL_CONTENT_URI }
        if (dir == "Audio") { uri = MediaStore.Audio.Media.EXTERNAL_CONTENT_URI }
        if (dir == "Videos") { uri = MediaStore.Video.Media.EXTERNAL_CONTENT_URI }
        //if (dir == "Documents") { uri = MediaStore.Files. }
        if (uri == null) { return r }
        if (dir.startsWith("Sdcard")) {
            val path = dir.replaceFirst("Sdcard", Environment.getExternalStorageDirectory().absolutePath)
            val fileDir = File(path) // Create a File object for the directory
            if (fileDir.exists() && fileDir.isDirectory) { // Check if it's a valid directory
                val listOfFiles: Array<File>? = fileDir.listFiles() // listFiles can return null
                if (listOfFiles != null) { // <<< ADD THIS NULL CHECK
                    for (file in listOfFiles) {
                        val f = JSONObject()
                        f.put("n", file.name)
                        if (file.isDirectory) {
                            f.put("t", 2)
                        } else {
                            f.put("t", 3)
                        }
                        f.put("s", file.length())
                        f.put("d", file.lastModified())
                        r.put(f)
                    }
                } else {
                    // Optional: Handle the case where listFiles() returned null
                    // (e.g., I/O error, or path wasn't a directory though you checked)
                    println("Warning: listFiles() returned null for path: $path")
                }
            } else {
                // Optional: Handle the case where the path doesn't exist or isn't a directory
                println("Warning: Path is not a valid directory: $path")
            }
        } else { // This is the 'else' branch for non-"Sdcard" paths
            parent.parent.getContentResolver().query( // Call query
                uri,
                projection,
                null,
                null,
                null
            )?.use { cursor -> // Safely use the cursor if not null; it will be auto-closed// 'cursor' here is non-null
                val titleColumn: Int = cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.DISPLAY_NAME)
                val dateModified: Int = cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.DATE_MODIFIED)
                val sizeColumn: Int = cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.SIZE)

                while (cursor.moveToNext()) {
                    val f = JSONObject()
                    f.put("n", cursor.getString(titleColumn))
                    f.put("t", 3) // Assuming type 3 for these files
                    f.put("s", cursor.getInt(sizeColumn))
                    f.put("d", cursor.getInt(dateModified)) // DATE_MODIFIED is usually Long (seconds since epoch)
                    r.put(f)
                }
            } // cursor.close() is automatically called here by the 'use' block
        }
        return r
    }

    fun deleteFile(path: String, filenames: JSONArray, req: JSONObject) {
        val fileArray: ArrayList<String> = ArrayList<String>()
        for (i in 0 until filenames.length()) {
            fileArray.add(filenames.getString(i))
        }

        val projection = arrayOf(
            MediaStore.MediaColumns._ID,
            MediaStore.MediaColumns.DISPLAY_NAME,
            MediaStore.MediaColumns.SIZE
        )
        var uri: Uri? = null
        if (path.startsWith("Sdcard")) {
            uri = Uri.fromFile(Environment.getExternalStorageDirectory())
        }
        if (path == "Images") {
            uri = MediaStore.Images.Media.EXTERNAL_CONTENT_URI
        }
        if (path == "Audio") {
            uri = MediaStore.Audio.Media.EXTERNAL_CONTENT_URI
        }
        if (path == "Videos") {
            uri = MediaStore.Video.Media.EXTERNAL_CONTENT_URI
        }
        //if (filenameSplit[0] == "Documents") { uri = MediaStore.Files. }
        if (uri == null) return

        if (path.startsWith("Sdcard")) {
            val filePath =
                path.replaceFirst("Sdcard", Environment.getExternalStorageDirectory().absolutePath)
            try {
                for (i in 0 until filenames.length()) {
                    fileArray.add(filenames.getString(i))
                    val file = File(filePath + "/" + filenames.getString(i))
                    if (file.exists()) {
                        if (file.delete()) {
                            fileDeleteResponse(req, true) // Send success
                        } else {
                            fileDeleteResponse(req, false) // Send failure
                        }
                    } else {
                        fileDeleteResponse(req, false) // Send failure, file not found
                    }
                }
            } catch (securityException: SecurityException) {
                fileDeleteResponse(req, false) // Send failure
            }
        } else { // For non-"Sdcard" paths, likely MediaStore URIs
            val fileidArray = ArrayList<String>() // Initialize outside to access later
            val fileUriArray = ArrayList<Uri>()   // Initialize outside to access later

            parent.parent.getContentResolver().query(
                uri,
                projection,
                null,
                null,
                null
            )?.use { cursor -> // Use safe call ?. and the 'use' block
                // cursor is non-null here
                val idColumn: Int = cursor.getColumnIndexOrThrow(MediaStore.MediaColumns._ID)
                val titleColumn: Int =
                    cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.DISPLAY_NAME)

                while (cursor.moveToNext()) {
                    val name = cursor.getString(titleColumn)
                    if (fileArray.contains(name)) { // fileArray is from method params
                        val id = cursor.getString(idColumn)
                        val contentUrl: Uri =
                            ContentUris.withAppendedId(uri, cursor.getLong(idColumn))
                        fileidArray.add(id)
                        fileUriArray.add(contentUrl)
                    }
                }
            } // cursor.close() is automatically called here

            // Now, fileidArray and fileUriArray are populated (if cursor wasn't null and contained matches)
            // Proceed with the deletion logic using these arrays
            if (fileUriArray.isNotEmpty()) { // Check if any files were actually found to delete
                for (i in 0 until fileUriArray.size) { // Iterate based on actual found files
                    try {
                        // It seems you're trying to match 'filenames' (parameter) with found files.
                        // The logic for matching 'req' to the correct deletion needs to be robust.
                        // Assuming 'req' is the original request for all filenames.
                        // If fileDeleteResponse needs to be sent per file, this loop structure is okay.
                        parent.parent.contentResolver.delete(fileUriArray[i], null, null)
                        // TODO: Review how 'req' and 'filenames' relate to 'fileUriArray' for correct response.
                        // It looks like you intend to send one response per file in 'filenames'.
                        // However, 'fileUriArray' might not have the same order or count if some files aren't found.
                        // For simplicity now, let's assume 'req' is general for the delete operation
                        // and you want to report success for each successful deletion from fileUriArray.
                        // A more robust approach might be to map original filenames to their URIs
                        // and then report success/failure for each originally requested file.

                        // This will send a success for EACH file successfully deleted from the fileUriArray.
                        // If you only want to send success if ALL files in `filenames` were deleted,
                        // this logic needs adjustment.
                        fileDeleteResponse(req, true) // Send success for this specific deletion
                    } catch (securityException: SecurityException) {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                            val recoverableSecurityException =
                                securityException as? RecoverableSecurityException
                                    ?: throw securityException

                            val activityCode = Random.nextInt() and 0xFFFF
                            // Ensure pad.args is correctly sourced if fileidArray is used
                            val pad = PendingActivityData(
                                this,
                                activityCode,
                                fileUriArray[i],
                                "${MediaStore.Images.Media._ID} = ?",
                                fileidArray[i],
                                req
                            )
                            pendingActivities.add(pad)

                            val intentSender =
                                recoverableSecurityException.userAction.actionIntent.intentSender
                            parent.parent.startIntentSenderForResult(
                                intentSender,
                                activityCode,
                                null,
                                0,
                                0,
                                0,
                                null
                            )
                        } else {
                            fileDeleteResponse(req, false) // Send fail for this specific deletion
                        }
                    } catch (e: Exception) {
                        // Catch any other exceptions during delete and report failure
                        println("MeshTunnel: Error deleting file ${fileUriArray[i]}. Error: ${e.message}")
                        // android.util.Log.e("MeshTunnel", "Error deleting file ${fileUriArray[i]}", e)
                        fileDeleteResponse(req, false) // Send fail for this specific deletion
                    }
                }
            } else {
                // No files matching the criteria in 'filenames' were found via MediaStore.
                // You might want to send a failure response for 'req' if 'filenames' was not empty,
                // indicating that none of the requested files could be processed for deletion.
                // For now, let's assume if filenames (input) was non-empty and fileUriArray (found) is empty,
                // it's a failure for the overall operation described by 'req'.
                if (filenames.length() > 0) {
                    println("MeshTunnel: No files found in MediaStore matching: ${filenames}")
                    // fileDeleteResponse(req, false) // Or handle as per your requirement
                }
            }
        }
    }

    fun deleteFileEx(pad: PendingActivityData) {
        try {
            val rowsDeleted = parent.parent.contentResolver.delete(pad.url, pad.where, arrayOf(pad.args))
            // Optionally, check rowsDeleted if it's important to know if something was actually deleted
            fileDeleteResponse(pad.req, true) // Send success
        } catch (e: Exception) { // Renamed and will be used
            println("MeshTunnel: Error deleting file via ContentResolver. URI: ${pad.url}, Where: ${pad.where}, Args: ${pad.args}. Error: ${e.message}")
            // android.util.Log.e("MeshTunnel", "Error deleting file via ContentResolver. URI: ${pad.url}, Where: ${pad.where}, Args: ${pad.args}", e)

            fileDeleteResponse(pad.req, false) // Send fail
        }
    }

    fun startFileTransfer(filename: String) {
        val filenameSplit = filename.split('/')
        //println("startFileTransfer: $filenameSplit")

        val projection = arrayOf(
                MediaStore.MediaColumns._ID,
                MediaStore.MediaColumns.DISPLAY_NAME,
                MediaStore.MediaColumns.SIZE
        )
        var uri : Uri? = null
        if (filenameSplit[0].startsWith("Sdcard")) { uri = Uri.fromFile(Environment.getExternalStorageDirectory()) }
        if (filenameSplit[0] == "Images") { uri = MediaStore.Images.Media.EXTERNAL_CONTENT_URI }
        if (filenameSplit[0] == "Audio") { uri = MediaStore.Audio.Media.EXTERNAL_CONTENT_URI }
        if (filenameSplit[0] == "Videos") { uri = MediaStore.Video.Media.EXTERNAL_CONTENT_URI }
        //if (filenameSplit[0] == "Documents") { uri = MediaStore.Files. }
        if (uri == null) { stopSocket(); return }

        if (filenameSplit[0].startsWith("Sdcard")) {
            val path = filename.replaceFirst("Sdcard", Environment.getExternalStorageDirectory().absolutePath)
            val file = File(path)

            if (file.exists() && file.isFile) { // Also check if it's a file, not a directory
                val fileName = file.name
                val fileSize = file.length()
                val eventArgs = JSONArray()
                eventArgs.put(fileName)
                eventArgs.put(fileSize)
                parent.logServerEventEx(106, eventArgs, "Download: ${fileName}, Size: $fileSize", serverData)

                val contentUrl = Uri.fromFile(file)
                try {
                    parent.parent.contentResolver.openInputStream(contentUrl).use { stream ->
                        if (stream == null) {
                            println("MeshTunnel: Failed to open input stream for (Sdcard) ${contentUrl}. Stream is null.")
                        } else {
                            // Serve the file
                            val buf = ByteArray(65535)
                            var len: Int
                            while (true) {
                                len = stream.read(buf, 0, buf.size) // Use buf.size for clarity
                                if (len <= 0) {
                                    // Stream is done or error
                                    if (len < 0) { // Read error
                                        println("MeshTunnel: Read error from stream for $fileName")
                                    }
                                    stopSocket() // Cleanly stop after successful or failed read
                                    break
                                }
                                if (_webSocket == null) { // Check before sending
                                    println("MeshTunnel: WebSocket became null during file transfer for $fileName.")
                                    // No need to call stopSocket() here as the outer loop/method handles it
                                    break
                                }
                                _webSocket?.send(buf.toByteString(0, len))

                                // Check queue size safely
                                val queueSize = _webSocket?.queueSize() ?: 0L
                                if (queueSize > 655350) {
                                    try {
                                        Thread.sleep(100)
                                    } catch (ie: InterruptedException) {
                                        Thread.currentThread().interrupt() // Restore interrupt status
                                        println("MeshTunnel: File transfer sleep interrupted for $fileName.")
                                        stopSocket() // Stop if interrupted
                                        break
                                    }
                                }
                            }
                        }
                    }
                    return // Successfully processed or handled stream closure
                } catch (fnfEx: FileNotFoundException) {
                    println("MeshTunnel: File not found when trying to open stream (Sdcard) for ${contentUrl}. Error: ${fnfEx.message}")
                    // android.util.Log.e("MeshTunnel", "FileNotFoundException for ${contentUrl}", fnfEx)
                } catch (ioEx: IOException) { // Catch other IO errors during read/write
                    println("MeshTunnel: IOException during file transfer (Sdcard) for ${contentUrl}. Error: ${ioEx.message}")
                    // android.util.Log.e("MeshTunnel", "IOException for ${contentUrl}", ioEx)
                    stopSocket() // Stop on other IO errors
                    return // Exit after handling IO error
                } catch (ex: Exception) { // Catch any other unexpected errors
                    println("MeshTunnel: Unexpected error during file transfer (Sdcard) for ${contentUrl}. Error: ${ex.message}")
                    // android.util.Log.e("MeshTunnel", "Unexpected error for ${contentUrl}", ex)
                    stopSocket()
                    return // Exit after handling unexpected error
                }
            } else {
                println("MeshTunnel: File does not exist or is not a file (Sdcard): $path")
                // No explicit stopSocket() needed here, will fall through.
            }
        }
        stopSocket()
    }

    override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
        //println("Tunnel-onClosing")
        stopSocket()
    }

    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
        println("Tunnel-onFailure ${t.toString()},  ${response.toString()}")
        stopSocket()
    }

    fun ByteArray.toHex(): String {
        return joinToString("") { "%02x".format(it) }
    }

    fun fileDeleteResponse(req: JSONObject, success: Boolean) {
        val json = JSONObject()
        json.put("action", "rm")
        json.put("reqid", req.getString("reqid"))
        json.put("success", success)
        if (_webSocket != null) { _webSocket?.send(json.toString().toByteArray().toByteString()) }

        // Event to the server
        val path = req.getString("path")
        val filenames = req.getJSONArray("delfiles")
        if (filenames.length() == 1) {
            val eventArgs = JSONArray()
            eventArgs.put(path + '/' + filenames[0])
            parent.logServerEventEx(45, eventArgs, "Delete: \"${path}/${filenames[0]}\"", serverData)
        }

        if (success && (lastDirRequest != null)) {
            val path = lastDirRequest?.getString("path")
            if ((path != null) && (path != "")) {
                lastDirRequest?.put("dir", getFolder(path))
                if (_webSocket != null) {_webSocket?.send(lastDirRequest?.toString()!!.toByteArray(Charsets.UTF_8).toByteString()) }
            }
        }
    }

    // WebRTC setup
    /*
    private fun initializePeerConnectionFactory() {
        //Initialize PeerConnectionFactory globals.
        val initializationOptions = PeerConnectionFactory.InitializationOptions.builder(parent.parent).createInitializationOptions()
        PeerConnectionFactory.initialize(initializationOptions)

        //Create a new PeerConnectionFactory instance - using Hardware encoder and decoder.
        val options = PeerConnectionFactory.Options()
        //val defaultVideoEncoderFactory = DefaultVideoEncoderFactory(rootEglBase?.eglBaseContext,  /* enableIntelVp8Encoder */true,  /* enableH264HighProfile */true)
        //val defaultVideoDecoderFactory = DefaultVideoDecoderFactory(rootEglBase?.eglBaseContext)
        val factory = PeerConnectionFactory.builder()
                .setOptions(options)
                //.setVideoEncoderFactory(defaultVideoEncoderFactory)
                //.setVideoDecoderFactory(defaultVideoDecoderFactory)
                .createPeerConnectionFactory()

        //factory.createPeerConnection()
    }
    */

}