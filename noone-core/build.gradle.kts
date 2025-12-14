plugins {
    java
    alias(libs.plugins.lombok)
}

group = "com.reajason.noone"
version = rootProject.version

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    implementation(libs.byte.buddy)
    implementation(libs.asm.commons)
    implementation(libs.okhttp3)
    implementation(libs.fastjson2)
    compileOnly(libs.javax.servlet.api)

    testImplementation(libs.junit.jupiter)
    testImplementation(libs.hamcrest)
    testRuntimeOnly(libs.junit.platform.launcher)
    testImplementation(libs.bundles.mockito)
}


tasks.test {
    useJUnitPlatform()
}