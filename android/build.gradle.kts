plugins {
    alias(libs.plugins.android.application) apply false
    // AGP 9 compiles Kotlin itself; only the Compose compiler plugin is added.
    alias(libs.plugins.kotlin.compose) apply false
}
