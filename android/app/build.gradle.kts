plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "me.ibrahimrafi.bwphone"
    compileSdk {
        version = release(libs.versions.compileSdk.get().toInt()) {
            minorApiLevel = libs.versions.compileSdkMinor.get().toInt()
        }
    }

    defaultConfig {
        applicationId = "me.ibrahimrafi.bwphone"
        minSdk = libs.versions.minSdk.get().toInt()
        targetSdk = libs.versions.targetSdk.get().toInt()
        // CI passes -PversionCode/-PversionName from the tag; local builds fall back.
        versionCode = (project.findProperty("versionCode") as String?)?.toInt() ?: 1
        versionName = (project.findProperty("versionName") as String?) ?: "0.1-dev"
        // Only the ABI we ship libbwphone_android.so for; JNA would otherwise
        // add its dispatch library for seven ABIs the app cannot run on.
        ndk { abiFilters += "arm64-v8a" }
    }

    // Release signing from the environment (CI), so the same key signs every
    // release and the phone accepts updates in place. Unset → unsigned release.
    val keystorePath = System.getenv("BWPHONE_KEYSTORE")
    if (keystorePath != null) {
        signingConfigs {
            create("release") {
                storeFile = file(keystorePath)
                storePassword = System.getenv("BWPHONE_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("BWPHONE_KEY_ALIAS")
                keyPassword = System.getenv("BWPHONE_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (keystorePath != null) signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }

    // libbwphone_android.so goes in src/main/jniLibs/<abi>/ (see README.md).
    sourceSets["main"].jniLibs.directories.add("src/main/jniLibs")
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        optIn.add("androidx.compose.material3.ExperimentalMaterial3ExpressiveApi")
        optIn.add("androidx.compose.material3.ExperimentalMaterial3Api")
    }
}

dependencies {
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.material3)
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material.icons)
    debugImplementation(libs.compose.ui.tooling)
    implementation(libs.graphics.shapes)
    implementation(libs.activity.compose)
    implementation(libs.lifecycle.runtime.compose)
    // Whether the app is in front: requests then open their screen directly.
    implementation(libs.lifecycle.process)

    implementation(libs.core.ktx)
    // BiometricPrompt needs a FragmentActivity host; AppCompatActivity is one.
    implementation(libs.appcompat)
    implementation(libs.biometric)
    implementation(libs.coroutines.android)
    // uniffi's generated Kotlin loads the .so through JNA.
    implementation(libs.jna) { artifact { type = "aar" } }
    implementation(libs.zxing.embedded)
}
