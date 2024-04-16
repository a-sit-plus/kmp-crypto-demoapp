package at.asitplus.cryptotest

import android.app.Application
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.CryptoAlgorithm
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.mobile.AndroidSpecificCryptoOps
import at.asitplus.crypto.mobile.ClientCrypto
import at.asitplus.crypto.mobile.TbaKey
import kotlinx.coroutines.asCoroutineDispatcher
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import kotlin.time.Duration


class AndroidApp : Application() {
    companion object {
        lateinit var INSTANCE: AndroidApp
    }

    override fun onCreate() {
        super.onCreate()
        INSTANCE = this
    }

    internal
    var cryptoOps: AndroidSpecificCryptoOps? = null
}

private var fragmentActivity: FragmentActivity? = null
var executor: Executor? = null
val ctx = Executors.newSingleThreadExecutor().asCoroutineDispatcher()

class AppActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            App()
            fragmentActivity = LocalContext.current as FragmentActivity
            executor = ContextCompat.getMainExecutor(fragmentActivity!!)
        }
    }
}

internal actual suspend fun generateKey(
    alg: CryptoAlgorithm,
    attestation: ByteArray?,
    withBiometricAuth: Duration?
): KmmResult<TbaKey> {
    AndroidApp.INSTANCE.cryptoOps = AndroidSpecificCryptoOps(
        withBiometricAuth,
        withBiometricAuth?.let { setupBiometric() })
    return if (attestation == null) ClientCrypto.createSigningKey(
        ALIAS,
        alg,
        AndroidApp.INSTANCE.cryptoOps!!,
    ).map { it as CryptoPublicKey.Ec to listOf() }
    else {
        ClientCrypto.createTbaP256Key(
            ALIAS,
            attestation,
            AndroidApp.INSTANCE.cryptoOps!!
        )
    }
}

fun setupBiometric(): AndroidSpecificCryptoOps.BiometricAuth {
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Biometric Auth")
        .setSubtitle("Authenticate private key usage")
        .setNegativeButtonText("Abort")
        .setAllowedAuthenticators(BIOMETRIC_STRONG)
        .build()

    val biometricPrompt = at.asitplus.crypto.mobile.BiometricPromptAdapter(
        fragmentActivity!!,
        executor!!
    )
    return AndroidSpecificCryptoOps.BiometricAuth(promptInfo, biometricPrompt)
}

internal actual suspend fun sign(
    data: ByteArray,
    alg: CryptoAlgorithm
): KmmResult<CryptoSignature> {
    println(AndroidApp.INSTANCE.cryptoOps)
    return ClientCrypto.sign(
        data,
        ALIAS,
        alg, AndroidApp.INSTANCE.cryptoOps!!
    )
}