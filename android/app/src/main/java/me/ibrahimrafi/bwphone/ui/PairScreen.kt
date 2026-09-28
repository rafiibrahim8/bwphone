package me.ibrahimrafi.bwphone.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Link
import androidx.compose.material.icons.rounded.QrCodeScanner
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LoadingIndicator
import androidx.compose.material3.MaterialShapes
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.graphics.shapes.RoundedPolygon
import me.ibrahimrafi.bwphone.PairActivity.Ui
import me.ibrahimrafi.bwphone.R

@Composable
fun PairScreen(
    ui: Ui,
    onMatch: () -> Unit,
    onNoMatch: () -> Unit,
    onScanAgain: () -> Unit,
    onClose: () -> Unit,
) {
    val cs = MaterialTheme.colorScheme
    Scaffold(
        containerColor = cs.surface,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.pair_title)) },
                navigationIcon = {
                    IconButton(onClick = onClose) { Icon(Icons.Rounded.Close, contentDescription = stringResource(R.string.close)) }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = cs.surface),
            )
        },
        bottomBar = {
            Column(
                Modifier.navigationBarsPadding().padding(horizontal = 16.dp, vertical = 16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                when (ui) {
                    is Ui.Confirm -> {
                        Button(onClick = onMatch, modifier = Modifier.fillMaxWidth().height(56.dp)) {
                            Text(stringResource(R.string.pair_match), style = MaterialTheme.typography.titleMedium)
                        }
                        TextButton(onClick = onNoMatch, modifier = Modifier.fillMaxWidth().height(56.dp)) {
                            Text(stringResource(R.string.pair_no_match), style = MaterialTheme.typography.titleMedium)
                        }
                    }
                    is Ui.Paired, Ui.AlreadyPaired -> Button(onClick = onClose, modifier = Modifier.fillMaxWidth().height(56.dp)) {
                        Text(stringResource(R.string.done), style = MaterialTheme.typography.titleMedium)
                    }
                    Ui.Scanning, Ui.Cancelled, is Ui.Failed -> Button(onClick = onScanAgain, modifier = Modifier.fillMaxWidth().height(56.dp)) {
                        Icon(Icons.Rounded.QrCodeScanner, contentDescription = null, modifier = Modifier.size(20.dp))
                        Text("  " + stringResource(R.string.pair_scan_again), style = MaterialTheme.typography.titleMedium)
                    }
                    else -> {}
                }
            }
        },
    ) { inner ->
        Column(
            Modifier.padding(inner).fillMaxSize().verticalScroll(rememberScrollState()),
        ) {
            when (ui) {
                is Ui.Confirm -> Words(ui.ip, ui.words)
                Ui.Scanning -> Message(Icons.Rounded.QrCodeScanner, MaterialShapes.Cookie9Sided, cs.secondaryContainer, cs.onSecondaryContainer, stringResource(R.string.pair_scan_title), stringResource(R.string.pair_scan))
                is Ui.Connecting -> Busy(stringResource(R.string.pair_connecting, ui.ip))
                is Ui.WaitingForPc -> Busy(stringResource(R.string.pair_waiting))
                is Ui.Paired -> Message(Icons.Rounded.Check, MaterialShapes.Sunny, cs.primaryContainer, cs.onPrimaryContainer, stringResource(R.string.pair_done_title), stringResource(R.string.pair_done_body, ui.ip))
                Ui.Cancelled -> Message(Icons.Rounded.Info, MaterialShapes.Cookie9Sided, cs.secondaryContainer, cs.onSecondaryContainer, stringResource(R.string.pair_cancelled_title), stringResource(R.string.pair_cancelled_body))
                is Ui.Failed -> Message(Icons.Rounded.ErrorOutline, MaterialShapes.SoftBurst, cs.errorContainer, cs.onErrorContainer, stringResource(R.string.pair_failed_title), stringResource(R.string.pair_failed_body, ui.reason))
                Ui.AlreadyPaired -> Message(Icons.Rounded.Link, MaterialShapes.Cookie9Sided, cs.secondaryContainer, cs.onSecondaryContainer, stringResource(R.string.pair_already_title), stringResource(R.string.pair_already_body))
            }
        }
    }
}

@Composable
private fun Words(ip: String, words: List<String>) {
    val cs = MaterialTheme.colorScheme
    Row(
        Modifier
            .padding(horizontal = 16.dp)
            .padding(top = 4.dp)
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(cs.surfaceContainer)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(Icons.Rounded.CheckCircle, contentDescription = null, tint = cs.primary)
        val prefix = stringResource(R.string.pair_connected)
        Text(
            buildAnnotatedString {
                append(prefix)
                withStyle(BwType.mono.toSpanStyle()) { append(ip) }
            },
            style = MaterialTheme.typography.bodyMedium,
            color = cs.onSurface,
        )
    }
    Text(
        stringResource(R.string.pair_check),
        style = BwType.heading,
        color = cs.onSurface,
        modifier = Modifier.padding(start = 24.dp, end = 24.dp, top = 28.dp, bottom = 20.dp),
    )
    // Numbered in reading order: the order matters.
    Column(Modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
        for (row in 0 until 3) {
            Row(horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                for (col in 0 until 2) {
                    val i = row * 2 + col
                    val big = 24.dp
                    val small = 6.dp
                    val shape = RoundedCornerShape(
                        topStart = if (i == 0) big else small,
                        topEnd = if (i == 1) big else small,
                        bottomStart = if (i == 4) big else small,
                        bottomEnd = if (i == 5) big else small,
                    )
                    Column(
                        Modifier
                            .weight(1f)
                            .clip(shape)
                            .background(cs.surfaceContainerHigh)
                            .padding(start = 16.dp, end = 16.dp, top = 12.dp, bottom = 14.dp),
                    ) {
                        Text("${i + 1}", style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.SemiBold), color = cs.primary)
                        Text(words.getOrElse(i) { "" }, style = BwType.word, color = cs.onSurface)
                    }
                }
            }
        }
    }
    Row(
        Modifier.padding(start = 24.dp, end = 24.dp, top = 20.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(Icons.Rounded.Info, contentDescription = null, tint = cs.onSurfaceVariant, modifier = Modifier.size(20.dp))
        Text(stringResource(R.string.pair_help), style = MaterialTheme.typography.bodyMedium, color = cs.onSurfaceVariant)
    }
}

@Composable
private fun Busy(text: String) {
    Column(
        Modifier.fillMaxWidth().padding(top = 96.dp, start = 24.dp, end = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        LoadingIndicator(Modifier.size(72.dp))
        Text(
            text,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 20.dp),
        )
    }
}

@Composable
private fun Message(icon: ImageVector, polygon: RoundedPolygon, container: Color, content: Color, title: String, body: String) {
    Column(Modifier.padding(horizontal = 24.dp, vertical = 16.dp)) {
        ShapeBadge(icon, polygon, container, content, size = 88.dp, iconSize = 40.dp)
        Text(title, style = BwType.heading, color = MaterialTheme.colorScheme.onSurface, modifier = Modifier.padding(top = 20.dp))
        Text(body, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 8.dp))
    }
}
