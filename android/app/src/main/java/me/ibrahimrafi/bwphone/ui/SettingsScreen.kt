package me.ibrahimrafi.bwphone.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.ChevronRight
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.Notifications
import androidx.compose.material.icons.rounded.Remove
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import me.ibrahimrafi.bwphone.R
import me.ibrahimrafi.bwphone.RateLimit

/**
 * The phone's own settings. Only this screen changes them; the PC has no
 * message that can: the two unlock limits per hour, and the way into the
 * system's notification settings for this app.
 */
@Composable
fun SettingsScreen(
    perAccount: Int,
    overall: Int,
    onPerAccount: (Int) -> Unit,
    onOverall: (Int) -> Unit,
    onReset: () -> Unit,
    onNotificationSettings: () -> Unit,
    onClose: () -> Unit,
) {
    val cs = MaterialTheme.colorScheme
    Scaffold(
        containerColor = cs.surface,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.settings)) },
                navigationIcon = {
                    IconButton(onClick = onClose) { Icon(Icons.Rounded.Close, contentDescription = stringResource(R.string.close)) }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = cs.surface),
            )
        },
    ) { inner ->
        Column(
            Modifier
                .padding(inner)
                .fillMaxSize()
                .verticalScroll(rememberScrollState()),
        ) {
            SectionHeader(stringResource(R.string.settings_limits))
            SegmentedGroup {
                val perAccountLabel = stringResource(R.string.settings_per_account)
                SegmentRow(
                    0, 2, perAccountLabel,
                    supporting = stringResource(R.string.settings_per_account_body),
                    trailing = { Stepper(perAccount, 1..RateLimit.MAX_PER_ACCOUNT, perAccountLabel, onPerAccount) },
                )
                val overallLabel = stringResource(R.string.settings_overall)
                SegmentRow(
                    1, 2, overallLabel,
                    supporting = stringResource(R.string.settings_overall_body),
                    // Below the per-account cap the overall one would never be the one that stops anything.
                    trailing = { Stepper(overall, perAccount..RateLimit.MAX_OVERALL, overallLabel, onOverall) },
                )
            }
            Text(
                stringResource(R.string.settings_limits_body),
                style = MaterialTheme.typography.bodyMedium,
                color = cs.onSurfaceVariant,
                modifier = Modifier.padding(start = 24.dp, end = 24.dp, top = 16.dp),
            )
            Text(
                stringResource(R.string.settings_limits_risk),
                style = MaterialTheme.typography.bodyMedium,
                color = cs.onSurfaceVariant,
                modifier = Modifier.padding(start = 24.dp, end = 24.dp, top = 8.dp),
            )
            val isDefault = perAccount == RateLimit.DEFAULT_PER_ACCOUNT && overall == RateLimit.DEFAULT_OVERALL
            TextButton(
                onClick = onReset,
                enabled = !isDefault,
                modifier = Modifier.padding(start = 12.dp, top = 8.dp),
            ) {
                Text(stringResource(R.string.settings_reset, RateLimit.DEFAULT_PER_ACCOUNT, RateLimit.DEFAULT_OVERALL))
            }

            SectionHeader(stringResource(R.string.settings_notifications))
            SegmentedGroup {
                SegmentRow(
                    0, 1, stringResource(R.string.notification_settings),
                    supporting = stringResource(R.string.settings_notifications_body),
                    onClick = onNotificationSettings,
                    leading = { Icon(Icons.Rounded.Notifications, contentDescription = null, tint = cs.onSurfaceVariant) },
                    trailing = { Icon(Icons.Rounded.ChevronRight, contentDescription = null, tint = cs.onSurfaceVariant) },
                )
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

/** − value +, bounded; each press is saved at once. */
@Composable
private fun Stepper(value: Int, range: IntRange, label: String, onChange: (Int) -> Unit) {
    val cs = MaterialTheme.colorScheme
    val valueDesc = stringResource(R.string.settings_value_desc, label, value)
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        FilledTonalIconButton(onClick = { onChange(value - 1) }, enabled = value > range.first) {
            Icon(Icons.Rounded.Remove, contentDescription = stringResource(R.string.settings_decrease, label))
        }
        Text(
            "$value",
            style = MaterialTheme.typography.titleMedium,
            color = cs.onSurface,
            textAlign = TextAlign.Center,
            modifier = Modifier.widthIn(min = 32.dp).semantics { contentDescription = valueDesc },
        )
        FilledTonalIconButton(onClick = { onChange(value + 1) }, enabled = value < range.last) {
            Icon(Icons.Rounded.Add, contentDescription = stringResource(R.string.settings_increase, label))
        }
    }
}
