package at.asitplus.cryptotest

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.wrapContentSize
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.LightMode
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.CryptoAlgorithm
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.cryptotest.theme.AppTheme
import at.asitplus.cryptotest.theme.LocalThemeIsDark
import io.github.aakira.napier.Napier
import io.ktor.util.encodeBase64
import kotlinx.coroutines.runBlocking
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds


const val ALIAS = "SIGeN" //TODO something's messed up if i change this on my device

@Composable
internal fun App() = AppTheme {
    var attestation by remember { mutableStateOf(false) }
    var biometricAuth by remember { mutableStateOf(false) }
    var selectedIndex by remember { mutableStateOf(0) }
    val algos = listOf(CryptoAlgorithm.ES256, CryptoAlgorithm.ES384, CryptoAlgorithm.ES512)
    var inputData by remember { mutableStateOf("Foo") }
    var currentKey by remember { mutableStateOf<KmmResult<CryptoPublicKey.Ec>?>(null) }
    var currentKeyStr by remember { mutableStateOf("<none>") }
    var signingPossible by remember { mutableStateOf(currentKey?.isSuccess == true) }
    var signatureData by remember { mutableStateOf("") }

    Column(modifier = Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing)) {

        Row(
            horizontalArrangement = Arrangement.Center
        ) {
            Text(
                text = "KMP Crypto Demo",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(16.dp)
            )

            Spacer(modifier = Modifier.weight(1.0f))

            var isDark by LocalThemeIsDark.current
            IconButton(
                onClick = { isDark = !isDark }
            ) {
                Icon(
                    modifier = Modifier.padding(8.dp).size(20.dp),
                    imageVector = if (isDark) Icons.Default.LightMode else Icons.Default.DarkMode,
                    contentDescription = null
                )
            }
        }

        var displayedKeySize by remember { mutableStateOf(" ▼ " + algos[selectedIndex]) }
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Row {
                Text(
                    "Attestation",
                    modifier = Modifier.padding(
                        start = 16.dp,
                        top = 16.dp,
                        end = 0.dp,
                        bottom = 16.dp
                    )
                )
                Checkbox(checked = attestation,
                    modifier = Modifier.padding(horizontal = 0.dp, vertical = 4.dp),
                    onCheckedChange = {
                        attestation = it
                        if (attestation) {
                            selectedIndex = 0
                            displayedKeySize = " ▽ " + algos[selectedIndex]
                        } else {
                            displayedKeySize = " ▼ " + algos[selectedIndex]
                        }
                    })
            }
            Row {
                Text(
                    "Biometric Auth",
                    modifier = Modifier.padding(
                        start = 16.dp,
                        top = 16.dp,
                        end = 0.dp,
                        bottom = 16.dp
                    )
                )
                Checkbox(checked = biometricAuth,
                    modifier = Modifier.padding(horizontal = 0.dp, vertical = 4.dp),
                    onCheckedChange = {
                        biometricAuth = it
                    })
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Key Type", modifier = Modifier.padding(16.dp))
            var expanded by remember { mutableStateOf(false) }
            Box(
                modifier = Modifier.fillMaxWidth().wrapContentSize(Alignment.TopStart)
                    .padding(16.dp).background(MaterialTheme.colorScheme.primary)
            ) {

                Text(
                    displayedKeySize,
                    modifier = Modifier.fillMaxWidth().align(Alignment.BottomStart)
                        .clickable(onClick = {
                            if (!attestation) {
                                expanded = true
                                displayedKeySize = " ▲ " + algos[selectedIndex]
                            }
                        }),
                    color = MaterialTheme.colorScheme.onPrimary

                )
                DropdownMenu(
                    expanded = expanded,
                    onDismissRequest = {
                        expanded = false
                        displayedKeySize = " ▼ " + algos[selectedIndex]
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    algos.forEachIndexed { index, s ->
                        DropdownMenuItem(text = { Text(text = s.toString()) },
                            onClick = {
                                selectedIndex = index
                                expanded = false
                                displayedKeySize = " ▼ " + algos[selectedIndex]
                            })
                    }
                }
            }
        }

        Button(
            onClick = {
                runBlocking {
                    currentKey = generateKey(
                        algos[selectedIndex],
                        attestation,
                        if (biometricAuth) 5.seconds else null
                    )
                    currentKeyStr = currentKey.toString()
                    signingPossible = currentKey?.isSuccess ?: false
                    Napier.w { "Signing possible: ${currentKey?.isSuccess}" }
                }
            },
            modifier = Modifier.fillMaxWidth().padding(16.dp)
        ) {
            Text("Generate New Key")
        }

        OutlinedTextField(value = currentKeyStr,
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            minLines = 1,
            maxLines = 5,
            textStyle = TextStyle.Default.copy(fontSize = 10.sp),
            readOnly = true, onValueChange = {}, label = { Text("Current Key") })


        OutlinedTextField(value = inputData,
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            enabled = true,
            minLines = 1,
            maxLines = 2,
            textStyle = TextStyle.Default.copy(fontSize = 10.sp),
            onValueChange = { inputData = it },
            label = { Text("Data to be signed") })

        Button(
            onClick = {
                runBlocking {
                    Napier.w { "input: $inputData" }
                    Napier.w { "signinKey: $currentKey" }
                    sign(
                        inputData.encodeToByteArray(),
                        algos[selectedIndex]
                    ).map { signatureData = it.encodeToTlv().prettyPrint() }
                }
            },
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            enabled = signingPossible
        ) {
            Text("Sign")
        }

        OutlinedTextField(value = signatureData,
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            minLines = 1,
            maxLines = 9,
            textStyle = TextStyle.Default.copy(fontSize = 10.sp),
            readOnly = true, onValueChange = {}, label = { Text("Detached Signature") })
    }
}

internal expect suspend fun generateKey(
    alg: CryptoAlgorithm,
    attestation: Boolean,
    withBiometricAuth: Duration?
): KmmResult<CryptoPublicKey.Ec>

internal expect suspend fun sign(data: ByteArray, alg: CryptoAlgorithm): KmmResult<CryptoSignature>