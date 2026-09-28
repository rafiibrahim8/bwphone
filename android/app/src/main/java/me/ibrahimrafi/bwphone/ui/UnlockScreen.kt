package me.ibrahimrafi.bwphone.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.RemoveCircleOutline
import androidx.compose.material.icons.rounded.WarningAmber
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularWavyProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialShapes
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.toShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import me.ibrahimrafi.bwphone.PendingRequest
import me.ibrahimrafi.bwphone.R

/**
 * Shapes by position, never by emoji: a shape must not hint which one is real.
 * All the same size and colour, so the eye reads five equal choices.
 */
private val PickShapes = listOf(
    MaterialShapes.Cookie7Sided,
    MaterialShapes.Clover4Leaf,
    MaterialShapes.Sunny,
    MaterialShapes.Pill,
    MaterialShapes.SoftBurst,
)

@Composable
fun UnlockScreen(
    pending: PendingRequest.Pending,
    emojis: List<String>,
    unlockCount: Int,
    lastUnlock: Long,
    onPick: (Int) -> Unit,
    onNone: () -> Unit,
    onExpired: () -> Unit,
) {
    val cs = MaterialTheme.colorScheme
    val remaining by produceState(pending.remainingMillis.coerceAtLeast(0)) {
        while (value > 0) {
            delay(100)
            value = pending.remainingMillis.coerceAtLeast(0)
        }
    }
    LaunchedEffect(remaining == 0L) { if (remaining == 0L) onExpired() }

    val warnings = buildList {
        if (pending.unexplainedSessions > 0) {
            add(pluralStringResource(R.plurals.unexplained_sessions, pending.unexplainedSessions, pending.unexplainedSessions))
        }
        if (pending.suspicious) add(stringResource(R.string.suspicious))
    }
    val compact = warnings.isNotEmpty()
    val whenText = rememberWhen()

    // The window is translucent over the lock screen; this is its scrim.
    Box(Modifier.fillMaxSize().background(cs.scrim.copy(alpha = 0.4f))) {
        Column(
            Modifier
                .statusBarsPadding()
                .padding(top = 16.dp)
                .fillMaxSize()
                .clip(RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp))
                .background(cs.surfaceContainerLow)
                .verticalScroll(rememberScrollState())
                .navigationBarsPadding()
                .padding(horizontal = 20.dp, vertical = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            for (w in warnings) {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .padding(bottom = 12.dp)
                        .clip(RoundedCornerShape(20.dp))
                        .background(cs.errorContainer)
                        .padding(horizontal = 16.dp, vertical = 14.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Icon(Icons.Rounded.WarningAmber, contentDescription = null, tint = cs.onErrorContainer)
                    Text(w, style = MaterialTheme.typography.bodyMedium, color = cs.onErrorContainer)
                }
            }

            val ring = if (compact) 96.dp else 124.dp
            val seconds = ((remaining + 999) / 1000).toInt()
            Box(Modifier.padding(top = 8.dp).size(ring), contentAlignment = Alignment.Center) {
                CircularWavyProgressIndicator(
                    progress = { remaining.toFloat() / pending.totalMillis },
                    modifier = Modifier.size(ring),
                    color = cs.primary,
                    trackColor = cs.secondaryContainer,
                )
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        "$seconds",
                        style = if (compact) BwType.count.copy(fontSize = 28.sp, lineHeight = 30.sp) else BwType.count,
                        color = cs.onSurface,
                    )
                    Text(stringResource(R.string.unlock_seconds_left), style = MaterialTheme.typography.labelMedium, color = cs.onSurfaceVariant)
                }
            }

            Text(
                stringResource(R.string.unlock_title, pending.label),
                style = if (compact) BwType.display.copy(fontSize = 34.sp, lineHeight = 38.sp) else BwType.display,
                color = cs.onSurface,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = if (compact) 12.dp else 20.dp),
            )
            Text(
                if (unlockCount == 0) stringResource(R.string.unlock_facts_first)
                else stringResource(
                    R.string.unlock_facts,
                    ordinal(unlockCount + 1).replaceFirstChar { it.uppercase() },
                    lastPhrase(lastUnlock, whenText),
                ),
                style = MaterialTheme.typography.bodyMedium,
                color = cs.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 6.dp),
            )

            Text(
                stringResource(R.string.unlock_ask),
                style = MaterialTheme.typography.titleMedium,
                color = cs.onSurface,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = if (compact) 16.dp else 32.dp, bottom = 14.dp),
            )

            val pick = if (compact) 88.dp else 96.dp
            val rows = listOf(0..2, 3..4)
            for ((r, range) in rows.withIndex()) {
                Row(
                    Modifier.padding(top = if (r == 0) 0.dp else 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    for (i in range) {
                        EmojiPick(
                            emoji = emojis[i],
                            index = i,
                            size = pick,
                            container = cs.surfaceContainerHighest,
                            onClick = { onPick(i) },
                        )
                    }
                }
            }

            Spacer(Modifier.height(if (compact) 20.dp else 28.dp))
            OutlinedButton(
                onClick = onNone,
                modifier = Modifier.fillMaxWidth().height(56.dp),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = cs.onSurface),
            ) {
                Icon(Icons.Rounded.RemoveCircleOutline, contentDescription = null, modifier = Modifier.size(20.dp))
                Spacer(Modifier.size(8.dp))
                Text(stringResource(R.string.none_of_these), style = MaterialTheme.typography.titleMedium)
            }
        }
    }
}

@Composable
private fun EmojiPick(emoji: String, index: Int, size: androidx.compose.ui.unit.Dp, container: Color, onClick: () -> Unit) {
    val desc = stringResource(R.string.unlock_emoji_desc, index + 1, emoji)
    val shape = PickShapes[index].toShape()
    Box(
        Modifier
            .size(size)
            .clip(shape)
            .background(container)
            .clickable(onClick = onClick)
            .semantics { contentDescription = desc },
        contentAlignment = Alignment.Center,
    ) {
        Text(emoji, fontSize = 40.sp)
    }
}

/** "at 09:14", "yesterday 22:40", or the date. */
@Composable
private fun lastPhrase(ts: Long, whenText: (Long, Boolean) -> String): String {
    val w = whenText(ts, false)
    return if (isToday(ts)) stringResource(R.string.at_time, w) else w
}
