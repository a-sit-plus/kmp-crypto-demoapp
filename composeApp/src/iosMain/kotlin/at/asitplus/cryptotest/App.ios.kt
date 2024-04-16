package at.asitplus.cryptotest

import at.asitplus.KmmResult
import at.asitplus.crypto.mobile.IosSpecificCryptoOps
import at.asitplus.crypto.datatypes.CryptoAlgorithm
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.mobile.ClientCrypto
import at.asitplus.crypto.mobile.TbaKey
import at.asitplus.crypto.mobile.evaluate
import io.github.aakira.napier.Napier
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import platform.LocalAuthentication.LAContext
import platform.LocalAuthentication.LAPolicyDeviceOwnerAuthentication
import platform.LocalAuthentication.LAPolicyDeviceOwnerAuthenticationWithBiometrics
import platform.Security.kSecAccessControlAnd
import platform.Security.kSecAccessControlBiometryCurrentSet
import platform.Security.kSecAccessControlDevicePasscode
import platform.Security.kSecAccessControlPrivateKeyUsage
import platform.Security.kSecAccessControlUserPresence
import kotlin.time.Duration


lateinit var opsForUse: IosSpecificCryptoOps

var authValidUntil: Instant? = null
var biometricTimeout: Duration? = null

@OptIn(ExperimentalForeignApi::class)
internal actual suspend fun generateKey(
    alg: CryptoAlgorithm,
    attestation: ByteArray?,
    withBiometricAuth: Duration?
): KmmResult<TbaKey> {
    withBiometricAuth?.also {
        authValidUntil = Clock.System.now() + it
        biometricTimeout = it
    } ?: run {
        authValidUntil = null
        biometricTimeout = null
    }
    val ctx= LAContext().apply {
        touchIDAuthenticationAllowableReuseDuration =
            biometricTimeout?.inWholeSeconds?.toDouble() ?: 0.0
    }
    opsForUse = IosSpecificCryptoOps(authCtx = ctx)

    val hasKey = ClientCrypto.hasKey(ALIAS, opsForUse)
    Napier.w { "Key with alias $ALIAS exists: $hasKey" }

    if (hasKey.getOrThrow()) {
        Napier.w { "trying to clear key" }
        println(ClientCrypto.deleteKey(ALIAS, opsForUse))
    }

    Napier.w { "creating signing key" }
    val opsForCreation = IosSpecificCryptoOps(
        secAccessControlFlags = withBiometricAuth?.let { kSecAccessControlBiometryCurrentSet }
            ?: 0uL,
        authCtx = ctx

    )
    return (if (attestation == null) {
        ClientCrypto.createSigningKey(
            ALIAS,
            alg,
            opsForCreation
        ).map { it as CryptoPublicKey.Ec to listOf() }
    } else ClientCrypto.createTbaP256Key(
        ALIAS,
        attestation,
        opsForCreation
    ))
}

@OptIn(ExperimentalForeignApi::class)
internal actual suspend fun sign(
    data: ByteArray,
    alg: CryptoAlgorithm
): KmmResult<CryptoSignature> {
    authValidUntil?.let {
        if (it < Clock.System.now()) {
            authValidUntil = Clock.System.now() + biometricTimeout!!
            opsForUse = IosSpecificCryptoOps(authCtx = LAContext().apply {
                touchIDAuthenticationAllowableReuseDuration =
                    biometricTimeout!!.inWholeSeconds.toDouble()
            })
        }
    }
    return ClientCrypto.sign(data, ALIAS, alg, opsForUse)
}

