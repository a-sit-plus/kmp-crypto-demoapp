package at.asitplus.cryptotest

import at.asitplus.KmmResult
import at.asitplus.crypto.mobile.IosSpecificCryptoOps
import at.asitplus.crypto.datatypes.CryptoAlgorithm
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.mobile.CryptoPrivateKey
import at.asitplus.crypto.mobile.IosPrivateKey
import at.asitplus.crypto.mobile.KmpCrypto
import at.asitplus.crypto.mobile.TbaKey
import io.github.aakira.napier.Napier
import io.ktor.util.encodeBase64
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import platform.LocalAuthentication.LAContext
import platform.Security.kSecAccessControlBiometryCurrentSet
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

private val AUTH_CONTAINER = Random.nextBytes(16).encodeBase64()

//TODO: this needs to be documented!
private var IosPrivateKey.authContainer: AuthContainer?
    get() = additionalData[AUTH_CONTAINER] as AuthContainer?
    set(value) {
        if (value != null)
            additionalData.put(AUTH_CONTAINER, value) else
            additionalData.remove(AUTH_CONTAINER)
    }

private fun IosPrivateKey.reAuth() {
    platformSpecifics = authContainer?.getAuthCtx() ?: AuthContainer.noAuth
}

private class AuthContainer(
    authValidUntil: Instant,
    private var opsForUse: IosSpecificCryptoOps
) {

    var authValidUntil: Instant
        private set

    init {
        this.authValidUntil = authValidUntil
    }

    @OptIn(ExperimentalForeignApi::class)
    fun getAuthCtx(): IosSpecificCryptoOps {
        if (authValidUntil < Clock.System.now()) {
            val touchIDAuthenticationAllowableReuseDuration =
                opsForUse.authCtx!!.touchIDAuthenticationAllowableReuseDuration
            authValidUntil =
                Clock.System.now() + touchIDAuthenticationAllowableReuseDuration.seconds!!
            opsForUse = IosSpecificCryptoOps(authCtx = LAContext().apply {
                this.touchIDAuthenticationAllowableReuseDuration =
                    touchIDAuthenticationAllowableReuseDuration
            })

        }
        return opsForUse
    }

    companion object {
        @OptIn(ExperimentalForeignApi::class)
        val noAuth = IosSpecificCryptoOps()
    }
}

@OptIn(ExperimentalForeignApi::class)
internal actual suspend fun generateKey(
    alg: CryptoAlgorithm,
    attestation: ByteArray?,
    withBiometricAuth: Duration?
): KmmResult<TbaKey> {
    val ctx = LAContext().apply {
        touchIDAuthenticationAllowableReuseDuration =
            withBiometricAuth?.inWholeSeconds?.toDouble() ?: 0.0
    }
    val opsForUse = IosSpecificCryptoOps(authCtx = ctx)
    val authContainer =
        withBiometricAuth?.let {
            AuthContainer(Clock.System.now() + it, opsForUse)
        }


    val hasKey = KmpCrypto.hasKey(ALIAS, opsForUse)
    Napier.w { "Key with alias $ALIAS exists: $hasKey" }

    if (hasKey.getOrThrow()) {
        Napier.w { "trying to clear key" }
        println(KmpCrypto.deleteKey(ALIAS, opsForUse))
    }

    Napier.w { "creating signing key" }
    val opsForCreation = IosSpecificCryptoOps(
        secAccessControlFlags = withBiometricAuth?.let { kSecAccessControlBiometryCurrentSet }
            ?: 0uL,
        authCtx = ctx
    )

    return (if (attestation == null) {
        KmpCrypto.createSigningKey(
            ALIAS,
            alg,
            opsForCreation
        ).map { it.apply { (first as IosPrivateKey).authContainer = authContainer } to listOf() }
    } else KmpCrypto.createTbaP256Key(
        ALIAS,
        attestation,
        opsForCreation
    )).map { it.apply { (first.first as IosPrivateKey).authContainer = authContainer } }
}

@OptIn(ExperimentalForeignApi::class)
internal actual suspend fun sign(
    data: ByteArray,
    alg: CryptoAlgorithm,
    signingKey: CryptoPrivateKey
): KmmResult<CryptoSignature> {
    if (signingKey !is IosPrivateKey) throw IllegalArgumentException("Not an iOS Private Key!")
    signingKey.reAuth()
    return KmpCrypto.sign(data, signingKey, alg)
}

internal actual suspend fun loadPubKey() = KmpCrypto.getPublicKey(ALIAS)

@OptIn(ExperimentalForeignApi::class)
internal actual suspend fun loadPrivateKey(): KmmResult<CryptoPrivateKey> =
    KmpCrypto.getPrivateKey(ALIAS, IosSpecificCryptoOps())