package at.asitplus.cryptotest

import android.app.Application
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricPrompt
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.CryptoAlgorithm
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.mobile.AndroidSpecificCryptoOps
import at.asitplus.crypto.mobile.ClientCrypto
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

class AppActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            App()
        }
    }
}

internal actual suspend fun generateKey(
    alg: CryptoAlgorithm,
    attestation: Boolean,
    withBiometricAuth: Duration?
): KmmResult<CryptoPublicKey.Ec> {
    AndroidApp.INSTANCE.cryptoOps = AndroidSpecificCryptoOps(withBiometricAuth != null, 0)
    return ClientCrypto.createSigningKey(
        ALIAS,
        alg,
        AndroidApp.INSTANCE.cryptoOps!!,
    ) as KmmResult<CryptoPublicKey.Ec>
}

@Composable
fun biometric() {
    val context = LocalContext.current

    val executor = remember { ContextCompat.getMainExecutor(context) }
    val biometricPrompt = BiometricPrompt(
        context as FragmentActivity,
        executor,
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                // handle authentication error here
            }

            @RequiresApi(Build.VERSION_CODES.R)
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                // handle authentication success here
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                // handle authentication failure here
            }
        }
    )
}

internal actual suspend fun sign(data: ByteArray, alg: CryptoAlgorithm): KmmResult<CryptoSignature> {
    println( AndroidApp.INSTANCE.cryptoOps)
   return  ClientCrypto.sign(
        data,
        ALIAS,
        alg,  AndroidApp.INSTANCE.cryptoOps!!
    )
}