rootProject.name = "CryptoTest-App"
include(":composeApp")

includeBuild("kmp-crypto") {
    dependencySubstitution {
        substitute(module("at.asitplus.crypto:datatypes")).using(project(":datatypes"))
        substitute(module("at.asitplus.crypto:datatypes-jws")).using(project(":datatypes-jws"))
        substitute(module("at.asitplus.crypto:datatypes-cose")).using(project(":datatypes-cose"))
    }
}

pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
        maven {
            url =
                uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
            name = "aspConventions"
        }
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        mavenLocal()
        maven(uri("https://raw.githubusercontent.com/a-sit-plus/kotlinx.serialization/mvn/repo"))
        maven("https://maven.pkg.jetbrains.space/kotlin/p/dokka/dev")
    }
}
