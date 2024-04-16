package at.asitplus.cryptotest

import at.asitplus.KmmResult
import at.asitplus.crypto.mobile.IosSpecificCryptoOps
import at.asitplus.crypto.datatypes.CryptoAlgorithm
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.mobile.ClientCrypto
import io.github.aakira.napier.Napier
import kotlinx.cinterop.ExperimentalForeignApi
import platform.LocalAuthentication.LAContext
import platform.LocalAuthentication.LAPolicyDeviceOwnerAuthentication
import platform.Security.kSecAccessControlBiometryCurrentSet
import at.asitplus.crypto.mobile.evaluate
import kotlin.time.Duration

val ctx: LAContext = LAContext()

@OptIn(ExperimentalForeignApi::class)
val opsWithContext = IosSpecificCryptoOps(authCtx = ctx)

@OptIn(ExperimentalForeignApi::class)
internal actual suspend fun generateKey(
    alg: CryptoAlgorithm,
    attestation: Boolean,
    withBiometricAuth: Duration?
): KmmResult<CryptoPublicKey.Ec> {
    withBiometricAuth?.also {
        ctx.apply {
            touchIDAuthenticationAllowableReuseDuration = (it.inWholeSeconds).toDouble()
        }
        Napier.w { "Trying to authenticate:" }
        ctx.evaluate(
            LAPolicyDeviceOwnerAuthentication, //either passcode or face if is fine. depending on what we used, we should be prompted for what was not done later on
            "Use Biometrics to authenticate"
        ).fold(onSuccess = { Napier.w { "LA Auth success: $it" } }) {
            Napier.e { "Error: ${it}" }
        }
    } ?: { ctx.touchIDAuthenticationAllowableReuseDuration = 0.0 }


    Napier.w { "Checking for key" }

    val hasKey = ClientCrypto.hasKey(ALIAS, opsWithContext)
    Napier.w { "Key with alias $ALIAS exists: $hasKey" }

    if (hasKey.getOrThrow()) {
        Napier.w { "trying to clear key" }
        println(ClientCrypto.deleteKey(ALIAS, opsWithContext))
    }

    Napier.w { "creating signing key" }
    val signinKey = ClientCrypto.createSigningKey(
        ALIAS,
        alg,
        IosSpecificCryptoOps(
            secAccessControlFlags = withBiometricAuth?.let { kSecAccessControlBiometryCurrentSet }
                ?: 0uL,
            authCtx = ctx
        )
    )

    return signinKey as KmmResult<CryptoPublicKey.Ec>

}

internal actual suspend fun sign(
    data: ByteArray,
    alg: CryptoAlgorithm
): KmmResult<CryptoSignature> = ClientCrypto.sign(data, ALIAS, alg, opsWithContext)
