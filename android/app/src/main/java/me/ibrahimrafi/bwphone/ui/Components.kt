package me.ibrahimrafi.bwphone.ui

import android.provider.Settings
import android.text.format.DateFormat
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialShapes
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.toPath
import androidx.compose.material3.toShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Matrix
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.graphics.shapes.Morph
import androidx.graphics.shapes.RoundedPolygon
import java.util.Calendar
import java.util.Date

/** A section's heading: small, primary-coloured, left-aligned with the list below it. */
@Composable
fun SectionHeader(text: String, color: Color = MaterialTheme.colorScheme.primary) {
    Text(
        text,
        style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.SemiBold),
        color = color,
        modifier = Modifier.padding(start = 24.dp, end = 24.dp, top = 24.dp, bottom = 8.dp),
    )
}

/** Rows of a segmented list: 4.dp corners inside, 20.dp at the group's two ends. */
fun segmentShape(index: Int, count: Int): Shape {
    val big = 20.dp
    val small = 4.dp
    val top = if (index == 0) big else small
    val bottom = if (index == count - 1) big else small
    return RoundedCornerShape(topStart = top, topEnd = top, bottomStart = bottom, bottomEnd = bottom)
}

@Composable
fun SegmentedGroup(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Column(modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(2.dp), content = content)
}

/** One row of a segmented list: leading slot, two lines of text, trailing slot. */
@Composable
fun SegmentRow(
    index: Int,
    count: Int,
    headline: String,
    modifier: Modifier = Modifier,
    supporting: String? = null,
    container: Color = MaterialTheme.colorScheme.surfaceContainer,
    headlineColor: Color = MaterialTheme.colorScheme.onSurface,
    supportingColor: Color = MaterialTheme.colorScheme.onSurfaceVariant,
    onClick: (() -> Unit)? = null,
    leading: (@Composable () -> Unit)? = null,
    trailing: (@Composable RowScope.() -> Unit)? = null,
) {
    Row(
        modifier
            .fillMaxWidth()
            .clip(segmentShape(index, count))
            .background(container)
            .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier)
            .heightIn(min = 56.dp)
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        leading?.invoke()
        Column(Modifier.weight(1f)) {
            Text(headline, style = MaterialTheme.typography.bodyLarge, color = headlineColor)
            if (supporting != null) Text(supporting, style = MaterialTheme.typography.bodyMedium, color = supportingColor)
        }
        trailing?.invoke(this)
    }
}

/** An icon inside one of the expressive shapes. */
@Composable
fun ShapeBadge(
    icon: ImageVector,
    polygon: RoundedPolygon,
    container: Color,
    content: Color,
    size: Dp = 40.dp,
    iconSize: Dp = 22.dp,
) {
    Box(
        Modifier.size(size).clip(polygon.toShape()).background(container),
        contentAlignment = Alignment.Center,
    ) {
        Icon(icon, contentDescription = null, tint = content, modifier = Modifier.size(iconSize))
    }
}

@Composable
fun LetterBadge(text: String, container: Color, content: Color) {
    Box(
        Modifier.size(40.dp).clip(MaterialShapes.Circle.toShape()).background(container),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text.take(1).uppercase(),
            style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.SemiBold),
            color = content,
        )
    }
}

/**
 * The listener's badge on Home: a cookie that slowly breathes into a clover
 * and back while it listens. Still when [animate] is false (not listening,
 * or animations turned off in the system).
 */
@Composable
fun MorphingBadge(
    icon: ImageVector,
    animate: Boolean,
    container: Color,
    content: Color,
    size: Dp = 96.dp,
) {
    val morph = remember { Morph(MaterialShapes.Cookie9Sided, MaterialShapes.Clover4Leaf) }
    val transition = rememberInfiniteTransition(label = "listener")
    val progress by if (animate) transition.animateFloat(
        0f, 1f, infiniteRepeatable(tween(4000), RepeatMode.Reverse), label = "morph",
    ) else remember { androidx.compose.runtime.mutableFloatStateOf(0f) }
    val angle by if (animate) transition.animateFloat(
        0f, 360f, infiniteRepeatable(tween(24_000, easing = LinearEasing)), label = "spin",
    ) else remember { androidx.compose.runtime.mutableFloatStateOf(0f) }
    val path = remember { Path() }
    val matrix = remember { Matrix() }
    Box(Modifier.size(size), contentAlignment = Alignment.Center) {
        Canvas(Modifier.size(size)) {
            path.rewind()
            morph.toPath(progress, path)
            matrix.reset()
            matrix.scale(this.size.width, this.size.height)
            path.transform(matrix)
            rotate(angle) { drawPath(path, container) }
        }
        Icon(icon, contentDescription = null, tint = content, modifier = Modifier.size(size * 0.38f))
    }
}

/** Whether the person turned animations off (Settings › Accessibility › Remove animations). */
@Composable
fun rememberAnimationsEnabled(): Boolean {
    val context = LocalContext.current
    return remember {
        Settings.Global.getFloat(context.contentResolver, Settings.Global.ANIMATOR_DURATION_SCALE, 1f) > 0f
    }
}

/** "09:14" today, "yesterday 22:40", otherwise the date and time. */
@Composable
fun rememberWhen(): (Long, Boolean) -> String {
    val context = LocalContext.current
    val res = LocalResources.current
    return remember(res) {
        { ts, capitalised ->
            val time = DateFormat.getTimeFormat(context).format(Date(ts))
            val then = Calendar.getInstance().apply { timeInMillis = ts }
            val now = Calendar.getInstance()
            val yesterday = Calendar.getInstance().apply { add(Calendar.DAY_OF_YEAR, -1) }
            fun sameDay(a: Calendar, b: Calendar) = a.get(Calendar.YEAR) == b.get(Calendar.YEAR) && a.get(Calendar.DAY_OF_YEAR) == b.get(Calendar.DAY_OF_YEAR)
            when {
                sameDay(then, now) -> time
                sameDay(then, yesterday) -> res.getString(
                    if (capitalised) me.ibrahimrafi.bwphone.R.string.yesterday_at else me.ibrahimrafi.bwphone.R.string.yesterday_lower, time,
                )
                else -> DateFormat.getMediumDateFormat(context).format(Date(ts)) + ", " + time
            }
        }
    }
}

fun isToday(ts: Long): Boolean {
    val then = Calendar.getInstance().apply { timeInMillis = ts }
    val now = Calendar.getInstance()
    return then.get(Calendar.YEAR) == now.get(Calendar.YEAR) && then.get(Calendar.DAY_OF_YEAR) == now.get(Calendar.DAY_OF_YEAR)
}

/** 1st, 2nd, 3rd, 4th … 11th, 12th, 13th, 21st. */
fun ordinal(n: Int): String {
    val suffix = if (n % 100 in 11..13) "th" else when (n % 10) { 1 -> "st"; 2 -> "nd"; 3 -> "rd"; else -> "th" }
    return "$n$suffix"
}
