plugins {
    id("war")
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    implementation("commons-fileupload:commons-fileupload:1.3.3")
    implementation("commons-beanutils:commons-beanutils:1.9.2")
    implementation("org.apache.tomcat.embed:tomcat-embed-websocket:8.5.96")
    implementation("org.apache.tomcat.embed:tomcat-embed-core:8.5.96")
    implementation(libs.javax.websocket.api)
    providedCompile("javax.servlet:servlet-api:2.5")
}

tasks.test {
    useJUnitPlatform()
}
