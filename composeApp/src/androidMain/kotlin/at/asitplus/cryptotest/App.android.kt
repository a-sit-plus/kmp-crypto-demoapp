package at.asitplus.cryptotest

import android.app.Application
import android.os.Bundle
import android.security.keystore.KeyProperties
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
import at.asitplus.crypto.provider.AndroidSpecificCryptoOps
import at.asitplus.crypto.provider.BiometricPromptAdapter
import at.asitplus.crypto.provider.CryptoPrivateKey
import at.asitplus.crypto.provider.KmpCrypto
import at.asitplus.crypto.provider.TbaKey
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
    val opsForUse = AndroidSpecificCryptoOps(
        keyGenCustomization = {
            withBiometricAuth?.also {
                setUserAuthenticationRequired(true)
                setUserAuthenticationParameters(
                    it.inWholeSeconds.toInt(),
                    KeyProperties.AUTH_BIOMETRIC_STRONG
                )
            } ?: setUserAuthenticationRequired(false)
        }) { setupBiometric() }
    return if (attestation == null) KmpCrypto.createSigningKey(
        ALIAS,
        alg,
        opsForUse,
    ).map { it to listOf() }
    else {
        KmpCrypto.createTbaP256Key(
            ALIAS,
            attestation,
            opsForUse
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

    val biometricPrompt = BiometricPromptAdapter(
        fragmentActivity!!,
        executor!!
    )
    return AndroidSpecificCryptoOps.BiometricAuth(promptInfo, biometricPrompt)
}

internal actual suspend fun sign(
    data: ByteArray,
    alg: CryptoAlgorithm,
    signingKey: CryptoPrivateKey
): KmmResult<CryptoSignature> {
    return KmpCrypto.sign(
        data,
        signingKey,
        alg
    )
}

internal actual suspend fun loadPubKey() = KmpCrypto.getPublicKey(ALIAS)
internal actual suspend fun loadPrivateKey() =
    KmpCrypto.getKeyPair(ALIAS, AndroidSpecificCryptoOps())