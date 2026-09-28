package me.ibrahimrafi.bwphone.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.Timer
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearWavyProgressIndicator
import androidx.compose.material3.MaterialShapes
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.toShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import me.ibrahimrafi.bwphone.EnrolState
import me.ibrahimrafi.bwphone.EnrolState.Phase
import me.ibrahimrafi.bwphone.R

@Composable
fun EnrolScreen(
    phase: Phase,
    openUntil: Long,
    onClose: () -> Unit,
    onDone: () -> Unit,
    onReopen: () -> Unit,
    onCancel: () -> Unit,
) {
    val cs = MaterialTheme.colorScheme
    Scaffold(
        containerColor = cs.surface,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.enrol_title)) },
                navigationIcon = {
                    IconButton(onClick = onClose) { Icon(Icons.Rounded.Close, contentDescription = stringResource(R.string.close)) }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = cs.surface),
            )
        },
        bottomBar = {
            Column(Modifier.navigationBarsPadding().padding(start = 16.dp, end = 16.dp, bottom = 16.dp, top = 8.dp)) {
                if (phase is Phase.Done || phase is Phase.Failed) {
                    FilledTonalButton(onClick = onDone, modifier = Modifier.fillMaxWidth().height(56.dp)) {
                        Text(stringResource(R.string.done), style = MaterialTheme.typography.titleMedium)
                    }
                } else {
                    Text(
                        stringResource(R.string.enrol_leave_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = cs.onSurfaceVariant,
                        modifier = Modifier.padding(start = 8.dp, end = 8.dp, bottom = 8.dp),
                    )
                    OutlinedButton(
                        onClick = onCancel,
                        modifier = Modifier.fillMaxWidth().height(56.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = cs.error),
                    ) {
                        Text(stringResource(R.string.enrol_cancel), style = MaterialTheme.typography.titleMedium)
                    }
                }
            }
        },
    ) { inner ->
        Column(
            Modifier
                .padding(inner)
                .fillMaxSize()
                .verticalScroll(rememberScrollState()),
        ) {
            when (phase) {
                is Phase.Done -> DoneCard(phase.label)
                is Phase.Failed -> FailedCard(phase.message)
                else -> InProgress(phase, openUntil, onReopen)
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun InProgress(phase: Phase, openUntil: Long, onReopen: () -> Unit) {
    val cs = MaterialTheme.colorScheme
    val label = when (phase) {
        is Phase.Creating -> phase.label
        is Phase.Compare -> phase.label
        is Phase.SelfTest -> phase.label
        else -> null
    }

    // The name: the PC's --label, final, shown as it arrives.
    Column(
        Modifier
            .padding(horizontal = 16.dp)
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(cs.surfaceContainer)
            .padding(horizontal = 16.dp, vertical = 12.dp),
    ) {
        Text(stringResource(R.string.enrol_name), style = MaterialTheme.typography.labelMedium, color = cs.primary)
        if (label != null) {
            Text(label, style = MaterialTheme.typography.titleLarge, color = cs.onSurface)
        } else {
            Text(stringResource(R.string.enrol_name_pending), style = MaterialTheme.typography.bodyLarge, color = cs.onSurfaceVariant)
        }
    }

    // The enrol window, until the pin closes it.
    if (phase is Phase.Waiting || phase is Phase.Creating || phase is Phase.Compare) {
        val remaining by produceState(openUntil - System.currentTimeMillis(), openUntil) {
            while (true) {
                value = (openUntil - System.currentTimeMillis()).coerceAtLeast(0)
                if (value == 0L) break
                delay(250)
            }
        }
        Column(
            Modifier
                .padding(start = 16.dp, end = 16.dp, top = 16.dp)
                .fillMaxWidth()
                .clip(RoundedCornerShape(20.dp))
                .background(cs.surfaceContainer)
                .padding(16.dp),
        ) {
            if (remaining > 0) {
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Icon(Icons.Rounded.Timer, contentDescription = null, tint = cs.primary, modifier = Modifier.size(22.dp))
                    val secs = (remaining / 1000).toInt()
                    val left = stringResource(R.string.enrol_window, "%d:%02d".format(secs / 60, secs % 60))
                    val suffix = stringResource(R.string.enrol_window_suffix)
                    Text(
                        buildAnnotatedString {
                            withStyle(SpanStyle(fontWeight = FontWeight.SemiBold)) { append(left) }
                            append(" ")
                            withStyle(BwType.mono.toSpanStyle()) { append("bwphone enroll") }
                            append(" ")
                            append(suffix)
                        },
                        style = MaterialTheme.typography.bodyLarge,
                        color = cs.onSurface,
                    )
                }
                LinearWavyProgressIndicator(
                    progress = { remaining.toFloat() / EnrolState.WINDOW_MS },
                    modifier = Modifier.padding(top = 14.dp).fillMaxWidth(),
                )
            } else {
                Text(stringResource(R.string.enrol_window_closed), style = MaterialTheme.typography.bodyLarge, color = cs.onSurface)
                TextButton(onClick = onReopen, modifier = Modifier.padding(top = 4.dp)) {
                    Text(stringResource(R.string.enrol_open_again))
                }
            }
        }
    }

    // The four steps, a real sequence.
    val current = when (phase) {
        Phase.Waiting -> 0
        is Phase.Creating -> 1
        is Phase.Compare -> 2
        is Phase.SelfTest -> 3
        else -> 4
    }
    val fingerprint = when (phase) {
        is Phase.Compare -> phase.fingerprint
        else -> null
    }
    Column(Modifier.padding(start = 24.dp, end = 24.dp, top = 24.dp)) {
        Step(1, stringResource(R.string.enrol_step_waiting), null, state(0, current), last = false)
        Step(
            2,
            stringResource(if (current == 1) R.string.enrol_step_creating else R.string.enrol_step_key),
            null, state(1, current), last = false,
        )
        Step(3, stringResource(R.string.enrol_step_compare), stringResource(R.string.enrol_step_compare_body).takeIf { current == 2 }, state(2, current), last = false) {
            if (fingerprint != null) {
                Text(
                    fingerprint,
                    style = BwType.fingerprint,
                    color = cs.onSurface,
                    modifier = Modifier
                        .padding(top = 10.dp)
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(16.dp))
                        .background(cs.surfaceContainerHigh)
                        .padding(horizontal = 16.dp, vertical = 14.dp),
                )
            }
        }
        Step(4, stringResource(R.string.enrol_step_selftest), stringResource(R.string.enrol_step_selftest_body).takeIf { current == 3 }, state(3, current), last = true)
    }
}

private enum class StepState { Done, Now, Next }

private fun state(step: Int, current: Int) = when {
    step < current -> StepState.Done
    step == current -> StepState.Now
    else -> StepState.Next
}

@Composable
private fun Step(
    number: Int,
    title: String,
    body: String?,
    state: StepState,
    last: Boolean,
    extra: @Composable () -> Unit = {},
) {
    val cs = MaterialTheme.colorScheme
    Row(Modifier.fillMaxWidth().height(androidx.compose.foundation.layout.IntrinsicSize.Min)) {
        Box(Modifier.width(32.dp).fillMaxHeight()) {
            if (!last) {
                Box(
                    Modifier
                        .align(Alignment.TopCenter)
                        .padding(top = 32.dp)
                        .width(1.5.dp)
                        .fillMaxHeight()
                        .background(cs.outlineVariant),
                )
            }
            val marker = Modifier.size(32.dp)
            when (state) {
                StepState.Done -> Box(marker.clip(CircleShape).background(cs.primary), contentAlignment = Alignment.Center) {
                    Icon(Icons.Rounded.Check, contentDescription = null, tint = cs.onPrimary, modifier = Modifier.size(18.dp))
                }
                StepState.Now -> Box(
                    Modifier.size(38.dp).align(Alignment.TopCenter).padding(0.dp).clip(MaterialShapes.Sunny.toShape()).background(cs.primaryContainer),
                    contentAlignment = Alignment.Center,
                ) {
                    Text("$number", style = MaterialTheme.typography.labelLarge.copy(fontWeight = FontWeight.Bold), color = cs.onPrimaryContainer)
                }
                StepState.Next -> Box(marker.clip(CircleShape).border(1.5.dp, cs.outline, CircleShape), contentAlignment = Alignment.Center) {
                    Text("$number", style = MaterialTheme.typography.labelLarge, color = cs.onSurfaceVariant)
                }
            }
        }
        Column(Modifier.padding(start = 16.dp, top = 5.dp, bottom = 20.dp).weight(1f)) {
            Text(
                title,
                style = MaterialTheme.typography.bodyLarge.copy(fontWeight = if (state == StepState.Now) FontWeight.SemiBold else FontWeight.Normal),
                color = if (state == StepState.Next) cs.onSurfaceVariant else cs.onSurface,
            )
            if (body != null) Text(body, style = MaterialTheme.typography.bodyMedium, color = cs.onSurfaceVariant)
            extra()
        }
    }
}

@Composable
private fun DoneCard(label: String) {
    val cs = MaterialTheme.colorScheme
    Column(Modifier.padding(horizontal = 24.dp, vertical = 16.dp)) {
        ShapeBadge(Icons.Rounded.Check, MaterialShapes.Sunny, cs.primaryContainer, cs.onPrimaryContainer, size = 88.dp, iconSize = 40.dp)
        Text(stringResource(R.string.enrol_done, label), style = BwType.heading, color = cs.onSurface, modifier = Modifier.padding(top = 20.dp))
        Text(stringResource(R.string.enrol_done_body), style = MaterialTheme.typography.bodyLarge, color = cs.onSurfaceVariant, modifier = Modifier.padding(top = 8.dp))
    }
}

@Composable
private fun FailedCard(message: String) {
    val cs = MaterialTheme.colorScheme
    Column(Modifier.padding(horizontal = 24.dp, vertical = 16.dp)) {
        ShapeBadge(Icons.Rounded.ErrorOutline, MaterialShapes.SoftBurst, cs.errorContainer, cs.onErrorContainer, size = 88.dp, iconSize = 40.dp)
        Text(stringResource(R.string.enrol_failed), style = BwType.heading, color = cs.onSurface, modifier = Modifier.padding(top = 20.dp))
        Text(message, style = MaterialTheme.typography.bodyLarge, color = cs.onSurfaceVariant, modifier = Modifier.padding(top = 8.dp))
    }
}
