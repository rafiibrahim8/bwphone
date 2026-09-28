package me.ibrahimrafi.bwphone.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialExpressiveTheme
import androidx.compose.material3.MotionScheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontVariation
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import me.ibrahimrafi.bwphone.R

/*
 * Material 3 Expressive from one seed, slate-teal #2F6468. Dynamic colour is
 * off on purpose: the unlock screen should look the same every time, and the
 * error roles keep their contrast whatever the wallpaper.
 */

private val Light = lightColorScheme(
    primary = Color(0xFF2A6A6F), onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFB1ECF1), onPrimaryContainer = Color(0xFF004F54),
    inversePrimary = Color(0xFF94D0D5),
    secondary = Color(0xFF4A6366), onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFCDE7EA), onSecondaryContainer = Color(0xFF334B4E),
    tertiary = Color(0xFF4F5C7E), onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFD7E1FF), onTertiaryContainer = Color(0xFF374466),
    error = Color(0xFFBA1A1A), onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFDAD6), onErrorContainer = Color(0xFF93000A),
    background = Color(0xFFF4FAFA), onBackground = Color(0xFF161D1E),
    surface = Color(0xFFF4FAFA), onSurface = Color(0xFF161D1E),
    surfaceVariant = Color(0xFFDAE4E5), onSurfaceVariant = Color(0xFF3F484A),
    surfaceTint = Color(0xFF2A6A6F),
    inverseSurface = Color(0xFF2B3232), inverseOnSurface = Color(0xFFECF2F2),
    outline = Color(0xFF6F797A), outlineVariant = Color(0xFFBFC8CA),
    scrim = Color(0xFF000000),
    surfaceBright = Color(0xFFF4FAFA), surfaceDim = Color(0xFFD5DBDB),
    surfaceContainerLowest = Color(0xFFFFFFFF), surfaceContainerLow = Color(0xFFEEF4F5),
    surfaceContainer = Color(0xFFE8EFEF), surfaceContainerHigh = Color(0xFFE2E9E9),
    surfaceContainerHighest = Color(0xFFDDE4E4),
)

private val Dark = darkColorScheme(
    primary = Color(0xFF94D0D5), onPrimary = Color(0xFF00363A),
    primaryContainer = Color(0xFF004F54), onPrimaryContainer = Color(0xFFB1ECF1),
    inversePrimary = Color(0xFF2A6A6F),
    secondary = Color(0xFFB1CBCE), onSecondary = Color(0xFF1C3437),
    secondaryContainer = Color(0xFF334B4E), onSecondaryContainer = Color(0xFFCDE7EA),
    tertiary = Color(0xFFB7C4EA), onTertiary = Color(0xFF212E4D),
    tertiaryContainer = Color(0xFF374466), onTertiaryContainer = Color(0xFFD7E1FF),
    error = Color(0xFFFFB4AB), onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A), onErrorContainer = Color(0xFFFFDAD6),
    background = Color(0xFF0E1415), onBackground = Color(0xFFDDE4E4),
    surface = Color(0xFF0E1415), onSurface = Color(0xFFDDE4E4),
    surfaceVariant = Color(0xFF3F484A), onSurfaceVariant = Color(0xFFBFC8CA),
    surfaceTint = Color(0xFF94D0D5),
    inverseSurface = Color(0xFFDDE4E4), inverseOnSurface = Color(0xFF2B3232),
    outline = Color(0xFF899294), outlineVariant = Color(0xFF3F484A),
    scrim = Color(0xFF000000),
    surfaceBright = Color(0xFF343A3B), surfaceDim = Color(0xFF0E1415),
    surfaceContainerLowest = Color(0xFF090F10), surfaceContainerLow = Color(0xFF161D1E),
    surfaceContainer = Color(0xFF1A2122), surfaceContainerHigh = Color(0xFF252B2C),
    surfaceContainerHighest = Color(0xFF2F3637),
)

/** Roboto Flex, bundled: downloadable fonts can't carry the width axis. */
private fun flex(weight: Int, width: Float = 100f) = Font(
    R.font.roboto_flex,
    weight = FontWeight(weight),
    variationSettings = FontVariation.Settings(FontVariation.weight(weight), FontVariation.width(width)),
)

private val Flex = FontFamily(flex(400), flex(500), flex(600), flex(700))

/** One family per emphasised width; each holds the single weight it is used at. */
private fun flexAt(weight: Int, width: Float) = FontFamily(flex(weight, width))

/** The few emphasised styles the design uses, beyond the Material scale. */
object BwType {
    /** "Unlock Work". */
    val display = TextStyle(fontFamily = flexAt(720, 124f), fontWeight = FontWeight(720), fontSize = 40.sp, lineHeight = 44.sp, letterSpacing = (-0.01).em)
    /** The listener status on Home. */
    val headline = TextStyle(fontFamily = flexAt(640, 116f), fontWeight = FontWeight(640), fontSize = 32.sp, lineHeight = 38.sp)
    /** Screen headings: Pair, Revoke. */
    val heading = TextStyle(fontFamily = flexAt(620, 112f), fontWeight = FontWeight(620), fontSize = 28.sp, lineHeight = 34.sp)
    /** The countdown's number. */
    val count = TextStyle(fontFamily = flexAt(560, 108f), fontWeight = FontWeight(560), fontSize = 36.sp, lineHeight = 36.sp)
    /** The six pairing words. */
    val word = TextStyle(fontFamily = flexAt(500, 104f), fontWeight = FontWeight(500), fontSize = 24.sp, lineHeight = 30.sp)
    /** The key fingerprint, the IP and the command: the only monospace. */
    val mono = TextStyle(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Medium, fontSize = 14.sp, lineHeight = 20.sp)
    val fingerprint = mono.copy(fontSize = 22.sp, lineHeight = 32.sp, letterSpacing = 0.06.em)
}

private val Base = Typography()

private val FlexTypography = Typography(
    displayLarge = Base.displayLarge.copy(fontFamily = Flex),
    displayMedium = Base.displayMedium.copy(fontFamily = Flex),
    displaySmall = Base.displaySmall.copy(fontFamily = Flex),
    headlineLarge = Base.headlineLarge.copy(fontFamily = Flex),
    headlineMedium = Base.headlineMedium.copy(fontFamily = Flex),
    headlineSmall = Base.headlineSmall.copy(fontFamily = Flex),
    titleLarge = Base.titleLarge.copy(fontFamily = Flex),
    titleMedium = Base.titleMedium.copy(fontFamily = Flex),
    titleSmall = Base.titleSmall.copy(fontFamily = Flex),
    bodyLarge = Base.bodyLarge.copy(fontFamily = Flex),
    bodyMedium = Base.bodyMedium.copy(fontFamily = Flex),
    bodySmall = Base.bodySmall.copy(fontFamily = Flex),
    labelLarge = Base.labelLarge.copy(fontFamily = Flex),
    labelMedium = Base.labelMedium.copy(fontFamily = Flex),
    labelSmall = Base.labelSmall.copy(fontFamily = Flex),
)

fun bwColors(dark: Boolean): ColorScheme = if (dark) Dark else Light

@Composable
fun BwTheme(dark: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    MaterialExpressiveTheme(
        colorScheme = bwColors(dark),
        typography = FlexTypography,
        motionScheme = MotionScheme.expressive(),
        content = content,
    )
}
