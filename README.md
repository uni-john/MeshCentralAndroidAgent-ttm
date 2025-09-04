# MeshCentral Agent for Android

This is the MeshCentral Agent for Android. It's a completely different code base from the agent used on Windows, Linux, macOS and FreeBSD. You can pair the agent to the server by scanning a QR code. Once paired, you can connect
to the server and see the device show up, see the battery state, device details and download pictures, audio and video files.

For more information, [visit MeshCentral.com](https://www.meshcentral.com).

## Social Media
[Reddit](https://www.reddit.com/r/MeshCentral/)  
[Twitter](https://twitter.com/MeshCentral)  
[BlogSpot](https://meshcentral2.blogspot.com/)

--

## Credit
Firstly, full credit to @Ylianst for the original project.

https://github.com/Ylianst/MeshCentralAndroidAgent

Second, further credit to @manfred-mueller for the subsequent auto-start fork.

https://github.com/manfred-mueller/MeshCentralAndroidAgent


## Fork reasons
This project was forked and updated to work with more modern android devices.

We had issues deploying the current 1.0.21 deployed from MeshCentral directly, with only 1.0.15 package providing a working share screen. 

This app currently targets SDK 34 (Android 10 and above).

**NOTE: It also hardcodes in the server connection URL for TTM.** <-- details on what and how to change below

This package can be signed to be deployed via .APK or .AAB for Managed Google Play Store deployments.

# Useful info
If you decide to use this, you need to know a few things:
1. It was developed for a specific client and is HARD CODED to join our Mesh Central deployment 
* You can adjust this in app/src/main/java/au/com/unison/meshagent/ttm/MainActivity.kt
* Edit the "val hardCodedServerLink : String? = " with your own registration linnk

2. Regardless of, but especially if you are planning to deploy this via MS Intune / Managed Android Apps / Google Play Enterprise apps
* You will need to update the namespace and refactor the app location
* First - update the app/build.gradle file with a new 'namespace' and 'applicationId' (match these)
* Second - find and replace in all files of the project the current 'namespace' from this project, 'au.com.unison.meshagent.ttm' with your new 'namespace'
* Third - refactor (change the folder structure) of the app\src\main\java sub-folder to match new namespace

3. Ensure when you build and deploy your app you increment you 'versionCode' and 'versionName' in app\build.gradle


This was updated and build using Android Studio.
It is signed and built via the Android Studio as well.
If you needed to align, compile and sign the src without Android Studio, you MIGHT be able to make the following generalised steps work.

## Manual steps to compile source that MIGHT work
1. Compile
apktool b MeshCentralAndroidAgent-ttm -o MeshCentralAndroidAgent-ttm-unsigned.apk

2. Align
zipalign -v 4 MeshCentralAndroidAgent-ttm-unsigned.apk MeshCentralAndroidAgent-ttm-aligned.apk

3. Sign
apksigner sign --ks keystore.jks --ks-key-alias key0 --out MeshCentralAndroidAgent-ttm-signed.apk MeshCentralAndroidAgent-ttm-aligned.apk
