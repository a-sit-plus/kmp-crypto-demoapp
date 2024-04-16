package at.asitplus.cryptotest

import android.app.Application
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.activity.compose.setContent
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
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
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
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
val ctx  = Executors.newSingleThreadExecutor().asCoroutineDispatcher()

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
    attestation: Boolean,
    withBiometricAuth: Duration?
): KmmResult<CryptoPublicKey.Ec> {
    AndroidApp.INSTANCE.cryptoOps = AndroidSpecificCryptoOps(
        withBiometricAuth != null,
        withBiometricAuth?.let { setupBiometric() })
    return ClientCrypto.createSigningKey(
        ALIAS,
        alg,
        AndroidApp.INSTANCE.cryptoOps!!,
    ) as KmmResult<CryptoPublicKey.Ec>
}

fun setupBiometric(): AndroidSpecificCryptoOps.BiometricAuth {
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Biometric Auth")
        .setSubtitle("Authenticate private key usage")
        .setNegativeButtonText("Abort")
        .setAllowedAuthenticators(BIOMETRIC_STRONG)
        .build()

    val chan =
        Channel<AndroidSpecificCryptoOps.BiometricAuth.AuthResult>(capacity = Channel.RENDEZVOUS)

    val biometricPrompt = BiometricPrompt(
        fragmentActivity!!,
        executor!!,
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                Log.w("BIOMETRIC", "Fail")
                CoroutineScope(ctx).launch {
                    chan.send(
                        AndroidSpecificCryptoOps.BiometricAuth.AuthResult.Failure(
                            errorCode,
                            errString
                        )
                    )
                }

            }

            @RequiresApi(Build.VERSION_CODES.R)
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
               Log.w("BIOMETRIC", "curreeded")
                CoroutineScope(executor!!.asCoroutineDispatcher()).launch {

                    Log.w("BIOMETRIC", "authed")
                    chan.send(
                        AndroidSpecificCryptoOps.BiometricAuth.AuthResult.Success(result)
                    )
                    Log.w("BIOMETRIC", "authed")
                }
            }

            override fun onAuthenticationFailed() {
                Log.w("BIOMETRIC", "ERR")
                CoroutineScope(ctx).launch {
                    chan.send(AndroidSpecificCryptoOps.BiometricAuth.AuthResult.Error())
                }
            }

        }
    )
    return AndroidSpecificCryptoOps.BiometricAuth(promptInfo, biometricPrompt, chan)
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