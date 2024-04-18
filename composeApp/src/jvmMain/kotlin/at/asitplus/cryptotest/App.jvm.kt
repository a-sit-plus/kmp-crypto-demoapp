package at.asitplus.cryptotest

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.CryptoAlgorithm
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.mobile.CryptoPrivateKey
import at.asitplus.crypto.mobile.JvmSpecifics
import at.asitplus.crypto.mobile.KmpCrypto
import at.asitplus.crypto.mobile.TbaKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyStore
import kotlin.time.Duration

val PROVIDER = BouncyCastleProvider()
val JVM_OPTS =
    JvmSpecifics(
        PROVIDER,
        KeyStore.getInstance("PKCS12", PROVIDER).apply { load(null, null) },
        privateKeyPassword = null
    )

internal actual suspend fun generateKey(
    alg: CryptoAlgorithm,
    attestation: ByteArray?,
    withBiometricAuth: Duration?,

    ): KmmResult<TbaKey> = KmpCrypto.createSigningKey(ALIAS, alg, JVM_OPTS).map { it to listOf() }

internal actual suspend fun sign(
    data: ByteArray,
    alg: CryptoAlgorithm,
    signingKey: CryptoPrivateKey
): KmmResult<CryptoSignature> = KmpCrypto.sign(data, signingKey, alg)

internal actual suspend fun loadPubKey() = KmpCrypto.getPublicKey(ALIAS, JVM_OPTS)
internal actual suspend fun loadPrivateKey() = KmpCrypto.getPrivateKey(ALIAS, JVM_OPTS)