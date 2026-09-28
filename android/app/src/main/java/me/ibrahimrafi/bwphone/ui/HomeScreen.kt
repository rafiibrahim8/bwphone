package me.ibrahimrafi.bwphone.ui

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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.BatteryChargingFull
import androidx.compose.material.icons.rounded.Block
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.DeleteForever
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.KeyOff
import androidx.compose.material.icons.rounded.Link
import androidx.compose.material.icons.rounded.LinkOff
import androidx.compose.material.icons.rounded.LockOpen
import androidx.compose.material.icons.rounded.MoreVert
import androidx.compose.material.icons.rounded.Notifications
import androidx.compose.material.icons.rounded.RemoveCircleOutline
import androidx.compose.material.icons.rounded.TimerOff
import androidx.compose.material.icons.rounded.Wifi
import androidx.compose.material.icons.rounded.WifiOff
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LoadingIndicator
import androidx.compose.material3.MaterialShapes
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.SheetValue
import androidx.compose.material3.rememberBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import me.ibrahimrafi.bwphone.AppState
import me.ibrahimrafi.bwphone.R

/** Everything Home shows, read from [me.ibrahimrafi.bwphone.Prefs] and the system. */
data class HomeData(
    val paired: Boolean,
    val pcAddress: String?,
    val accounts: List<Account>,
    val history: List<Event>,
    val batteryExempt: Boolean,
    val notificationsAllowed: Boolean,
) {
    data class Account(
        val id: String,
        val label: String,
        val unlocks: Int,
        val lastUnlock: Long,
        val invalidated: Boolean,
        /** Created on the phone but never pinned: the enrolment didn't finish. */
        val unfinished: Boolean,
    )

    data class Event(val time: Long, val label: String, val result: String)
}

interface HomeActions {
    fun pair()
    fun enrol()
    fun fixBattery()
    fun fixNotifications()
    fun notificationSettings()
    fun revoke(accountHex: String)
    fun revokeAll()
}

private sealed interface Sheet {
    object Pick : Sheet
    data class One(val account: HomeData.Account) : Sheet
    object All : Sheet
}

@Composable
fun HomeScreen(
    data: HomeData?,
    listener: AppState.Listener,
    actions: HomeActions,
    /** Opens with the Revoke sheet for this account up; for the debug gallery. */
    revoking: String? = null,
) {
    val cs = MaterialTheme.colorScheme
    var sheet by remember { mutableStateOf<Sheet?>(data?.accounts?.firstOrNull { it.label == revoking }?.let { Sheet.One(it) }) }
    var showAll by rememberSaveable { mutableStateOf(false) }
    var menu by remember { mutableStateOf(false) }
    val whenText = rememberWhen()

    Box(Modifier.fillMaxSize()) {
        if (data == null) {
            LoadingIndicator(Modifier.align(Alignment.Center))
            return@Box
        }
        LazyColumn(
            Modifier.fillMaxSize().statusBarsPadding(),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(bottom = 32.dp),
        ) {
            item {
                Row(
                    Modifier.fillMaxWidth().height(56.dp).padding(start = 24.dp, end = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        stringResource(R.string.app_name),
                        style = MaterialTheme.typography.labelLarge,
                        color = cs.onSurfaceVariant,
                        modifier = Modifier.weight(1f),
                    )
                    Box {
                        IconButton(onClick = { menu = true }) {
                            Icon(Icons.Rounded.MoreVert, contentDescription = stringResource(R.string.more_options))
                        }
                        DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.notification_settings)) },
                                leadingIcon = { Icon(Icons.Rounded.Notifications, contentDescription = null) },
                                onClick = { menu = false; actions.notificationSettings() },
                            )
                        }
                    }
                }
            }

            item { Hero(data, listener) }

            if (!data.paired) {
                item {
                    Button(
                        onClick = actions::pair,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 16.dp).fillMaxWidth().height(56.dp),
                    ) {
                        Icon(Icons.Rounded.Link, contentDescription = null, modifier = Modifier.size(20.dp))
                        Spacer(Modifier.size(8.dp))
                        Text(stringResource(R.string.pair), style = MaterialTheme.typography.titleMedium)
                    }
                }
            } else {
                item { SectionHeader(stringResource(R.string.accounts)) }
                item { Accounts(data.accounts, whenText) }
                item {
                    FilledTonalButton(
                        onClick = actions::enrol,
                        modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 12.dp).fillMaxWidth().height(56.dp),
                    ) {
                        Icon(Icons.Rounded.Add, contentDescription = null, modifier = Modifier.size(20.dp))
                        Spacer(Modifier.size(8.dp))
                        Text(stringResource(R.string.enrol), style = MaterialTheme.typography.titleMedium)
                    }
                }
            }

            item { SectionHeader(stringResource(R.string.setup_checks)) }
            item { Checks(data, actions) }

            if (data.paired) {
                item { SectionHeader(stringResource(R.string.recent_activity)) }
                item {
                    val events = if (showAll) data.history else data.history.take(5)
                    Activity(events, whenText)
                    if (data.history.size > 5) {
                        TextButton(onClick = { showAll = !showAll }, modifier = Modifier.padding(start = 12.dp, top = 4.dp)) {
                            Text(stringResource(if (showAll) R.string.show_less else R.string.show_all))
                        }
                    }
                }

                item { SectionHeader(stringResource(R.string.revoke), color = cs.error) }
                item {
                    val rows = buildList {
                        if (data.accounts.isNotEmpty()) add(0)
                        add(1)
                        add(2)
                    }
                    SegmentedGroup {
                        rows.forEachIndexed { i, row ->
                            when (row) {
                                0 -> SegmentRow(
                                    i, rows.size, stringResource(R.string.revoke_one),
                                    supporting = stringResource(R.string.revoke_one_body),
                                    headlineColor = cs.error,
                                    onClick = {
                                        sheet = if (data.accounts.size == 1) Sheet.One(data.accounts[0]) else Sheet.Pick
                                    },
                                    leading = { Icon(Icons.Rounded.KeyOff, contentDescription = null, tint = cs.error) },
                                )
                                1 -> SegmentRow(
                                    i, rows.size, stringResource(R.string.revoke_all),
                                    supporting = stringResource(R.string.revoke_all_body),
                                    headlineColor = cs.error,
                                    onClick = { sheet = Sheet.All },
                                    leading = { Icon(Icons.Rounded.DeleteForever, contentDescription = null, tint = cs.error) },
                                )
                                else -> SegmentRow(
                                    i, rows.size, stringResource(R.string.paired_note),
                                    container = cs.surfaceContainerLow,
                                    headlineColor = cs.onSurfaceVariant,
                                    leading = { Icon(Icons.Rounded.Link, contentDescription = null, tint = cs.onSurfaceVariant) },
                                )
                            }
                        }
                    }
                }
            }
            item { Spacer(Modifier.navigationBarsPadding()) }
        }
    }

    sheet?.let { current ->
        RevokeSheet(
            sheet = current,
            accounts = data?.accounts.orEmpty(),
            onPick = { sheet = Sheet.One(it) },
            onConfirm = {
                when (current) {
                    is Sheet.One -> actions.revoke(current.account.id)
                    Sheet.All -> actions.revokeAll()
                    Sheet.Pick -> {}
                }
            },
            onDismiss = { sheet = null },
        )
    }
}

@Composable
private fun Hero(data: HomeData, listener: AppState.Listener) {
    val cs = MaterialTheme.colorScheme
    val animations = rememberAnimationsEnabled()
    val listening = data.paired && listener is AppState.Listener.Listening
    Column(Modifier.padding(start = 24.dp, end = 24.dp, top = 4.dp, bottom = 12.dp)) {
        MorphingBadge(
            icon = when {
                !data.paired -> Icons.Rounded.LinkOff
                listening -> Icons.Rounded.Wifi
                else -> Icons.Rounded.WifiOff
            },
            animate = listening && animations,
            container = if (listening) cs.primaryContainer else cs.surfaceContainerHighest,
            content = if (listening) cs.onPrimaryContainer else cs.onSurfaceVariant,
        )
        Text(
            stringResource(
                when {
                    !data.paired -> R.string.home_not_paired
                    listening -> R.string.home_listening
                    listener is AppState.Listener.Stopped -> R.string.home_starting
                    else -> R.string.home_off_wifi
                }
            ),
            style = BwType.headline,
            color = cs.onSurface,
            modifier = Modifier.padding(top = 20.dp),
        )
        val body = when {
            !data.paired -> stringResource(R.string.home_not_paired_body)
            listener is AppState.Listener.OffWifi -> stringResource(R.string.home_off_wifi_body)
            else -> null
        }
        if (body != null) {
            Text(body, style = MaterialTheme.typography.bodyMedium, color = cs.onSurfaceVariant, modifier = Modifier.padding(top = 8.dp))
        } else if (data.pcAddress != null) {
            val prefix = stringResource(R.string.home_paired_seen)
            Text(
                buildAnnotatedString {
                    append(prefix)
                    withStyle(BwType.mono.toSpanStyle()) { append(data.pcAddress) }
                },
                style = MaterialTheme.typography.bodyMedium,
                color = cs.onSurfaceVariant,
                modifier = Modifier.padding(top = 8.dp),
            )
        }
    }
}

@Composable
private fun Accounts(accounts: List<HomeData.Account>, whenText: (Long, Boolean) -> String) {
    val cs = MaterialTheme.colorScheme
    if (accounts.isEmpty()) {
        Text(
            stringResource(R.string.no_accounts),
            style = MaterialTheme.typography.bodyMedium,
            color = cs.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 24.dp),
        )
        return
    }
    val tones = listOf(
        cs.tertiaryContainer to cs.onTertiaryContainer,
        cs.secondaryContainer to cs.onSecondaryContainer,
        cs.primaryContainer to cs.onPrimaryContainer,
    )
    SegmentedGroup {
        accounts.forEachIndexed { i, a ->
            val broken = a.invalidated || a.unfinished
            val supporting = when {
                a.invalidated -> stringResource(R.string.account_invalidated)
                a.unfinished -> stringResource(R.string.account_unfinished)
                a.unlocks == 0 -> stringResource(R.string.account_no_unlocks)
                else -> pluralStringResource(R.plurals.account_unlocks, a.unlocks, a.unlocks, whenText(a.lastUnlock, false))
            }
            SegmentRow(
                i, accounts.size, a.label,
                supporting = supporting,
                container = if (broken) cs.errorContainer else cs.surfaceContainer,
                headlineColor = if (broken) cs.onErrorContainer else cs.onSurface,
                supportingColor = if (broken) cs.onErrorContainer else cs.onSurfaceVariant,
                leading = {
                    if (broken) {
                        ShapeBadge(Icons.Rounded.KeyOff, MaterialShapes.Circle, cs.error, cs.onError, iconSize = 20.dp)
                    } else {
                        val (bg, fg) = tones[i % tones.size]
                        LetterBadge(a.label, bg, fg)
                    }
                },
            )
        }
    }
}

@Composable
private fun Checks(data: HomeData, actions: HomeActions) {
    val cs = MaterialTheme.colorScheme
    data class Check(val ok: Boolean, val icon: ImageVector, val title: Int, val off: Int, val action: Int, val fix: () -> Unit)
    val checks = listOf(
        Check(data.batteryExempt, Icons.Rounded.BatteryChargingFull, R.string.check_battery, R.string.check_battery_off, R.string.allow, actions::fixBattery),
        Check(data.notificationsAllowed, Icons.Rounded.Notifications, R.string.check_notifications, R.string.check_notifications_off, R.string.allow, actions::fixNotifications),
    )
    SegmentedGroup {
        checks.forEachIndexed { i, c ->
            SegmentRow(
                i, checks.size, stringResource(c.title),
                supporting = if (c.ok) null else stringResource(c.off),
                leading = { Icon(c.icon, contentDescription = null, tint = cs.onSurfaceVariant) },
                trailing = {
                    if (c.ok) {
                        Icon(Icons.Rounded.CheckCircle, contentDescription = null, tint = cs.primary)
                    } else {
                        FilledTonalButton(onClick = c.fix, contentPadding = ButtonDefaults.SmallContentPadding) {
                            Text(stringResource(c.action))
                        }
                    }
                },
            )
        }
    }
}

@Composable
private fun Activity(events: List<HomeData.Event>, whenText: (Long, Boolean) -> String) {
    val cs = MaterialTheme.colorScheme
    if (events.isEmpty()) {
        Text(
            stringResource(R.string.no_activity),
            style = MaterialTheme.typography.bodyMedium,
            color = cs.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 24.dp),
        )
        return
    }
    SegmentedGroup {
        events.forEachIndexed { i, e ->
            val (icon, title, body) = when (e.result) {
                "ok" -> Triple(Icons.Rounded.LockOpen, stringResource(R.string.act_ok, e.label), null)
                "denied" -> Triple(Icons.Rounded.Block, stringResource(R.string.act_denied, e.label), stringResource(R.string.act_denied_body))
                "rejected" -> Triple(Icons.Rounded.RemoveCircleOutline, stringResource(R.string.act_rejected, e.label), stringResource(R.string.act_rejected_body))
                "expired" -> Triple(Icons.Rounded.TimerOff, stringResource(R.string.act_expired, e.label), stringResource(R.string.act_expired_body))
                "invalidated" -> Triple(Icons.Rounded.KeyOff, stringResource(R.string.act_invalidated, e.label), stringResource(R.string.account_invalidated))
                "cancelled by PC" -> Triple(Icons.Rounded.LinkOff, stringResource(R.string.act_cancelled, e.label), stringResource(R.string.act_cancelled_body))
                else -> Triple(Icons.Rounded.ErrorOutline, stringResource(R.string.act_error, e.label), null)
            }
            val alarming = e.result == "denied" || e.result == "rejected"
            SegmentRow(
                i, events.size, title,
                supporting = body,
                headlineColor = if (alarming) cs.error else cs.onSurface,
                leading = { Icon(icon, contentDescription = null, tint = if (alarming) cs.error else cs.onSurfaceVariant) },
                trailing = {
                    Text(whenText(e.time, true), style = MaterialTheme.typography.labelMedium, color = cs.onSurfaceVariant)
                },
            )
        }
    }
}

@Composable
private fun RevokeSheet(
    sheet: Sheet,
    accounts: List<HomeData.Account>,
    onPick: (HomeData.Account) -> Unit,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    val cs = MaterialTheme.colorScheme
    val state = rememberBottomSheetState(SheetValue.Hidden, setOf(SheetValue.Hidden, SheetValue.Expanded))
    val scope = rememberCoroutineScope()
    fun close(then: () -> Unit = {}) {
        scope.launch { state.hide() }.invokeOnCompletion { then(); onDismiss() }
    }
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = state, containerColor = cs.surfaceContainerLow) {
        Column(Modifier.padding(start = 24.dp, end = 24.dp, bottom = 24.dp).navigationBarsPadding()) {
            when (sheet) {
                Sheet.Pick -> {
                    Text(stringResource(R.string.revoke_which), style = BwType.heading, color = cs.onSurface, modifier = Modifier.padding(bottom = 16.dp))
                    Column(Modifier.padding(horizontal = 0.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        accounts.forEachIndexed { i, a ->
                            SegmentRow(
                                i, accounts.size, a.label,
                                container = cs.surfaceContainerHigh,
                                onClick = { onPick(a) },
                                leading = { Icon(Icons.Rounded.KeyOff, contentDescription = null, tint = cs.error) },
                            )
                        }
                    }
                    OutlinedButton(onClick = { close() }, modifier = Modifier.padding(top = 20.dp).fillMaxWidth().height(56.dp)) {
                        Text(stringResource(R.string.cancel), style = MaterialTheme.typography.titleMedium)
                    }
                }
                is Sheet.One, Sheet.All -> {
                    ShapeBadge(Icons.Rounded.KeyOff, MaterialShapes.SoftBurst, cs.errorContainer, cs.onErrorContainer, size = 72.dp, iconSize = 32.dp)
                    val title: String
                    val paragraphs: List<String>
                    val confirm: String
                    if (sheet is Sheet.One) {
                        val label = sheet.account.label
                        val others = accounts.filter { it.id != sheet.account.id }.map { it.label }
                        title = stringResource(R.string.revoke_title, label)
                        confirm = stringResource(R.string.revoke_confirm, label)
                        paragraphs = buildList {
                            add(stringResource(R.string.revoke_body, label))
                            if (others.size == 1) add(stringResource(R.string.revoke_other_keeps, others[0]))
                            else if (others.size > 1) add(stringResource(R.string.revoke_others_keep, joinNames(others)))
                            add(stringResource(R.string.revoke_undo, label))
                        }
                    } else {
                        title = stringResource(R.string.revoke_all_title)
                        confirm = stringResource(R.string.revoke_all_confirm)
                        paragraphs = listOf(stringResource(R.string.revoke_all_sheet_body))
                    }
                    Text(title, style = BwType.heading, color = cs.onSurface, modifier = Modifier.padding(top = 18.dp))
                    Text(
                        paragraphs.joinToString(" "),
                        style = MaterialTheme.typography.bodyLarge,
                        color = cs.onSurfaceVariant,
                        modifier = Modifier.padding(top = 10.dp),
                    )
                    Column(Modifier.padding(top = 24.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = { close(onConfirm) },
                            colors = ButtonDefaults.buttonColors(containerColor = cs.error, contentColor = cs.onError),
                            modifier = Modifier.fillMaxWidth().height(56.dp),
                        ) {
                            Text(confirm, style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Medium))
                        }
                        OutlinedButton(onClick = { close() }, modifier = Modifier.fillMaxWidth().height(56.dp)) {
                            Text(stringResource(R.string.keep), style = MaterialTheme.typography.titleMedium)
                        }
                    }
                }
            }
        }
    }
}

/** "Personal", "Personal and Family", "Personal, Family and Travel". */
private fun joinNames(names: List<String>): String =
    if (names.size <= 1) names.joinToString() else names.dropLast(1).joinToString(", ") + " and " + names.last()
