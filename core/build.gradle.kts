plugins {
    `java-library`
}

fun DependencyHandlerScope.externalLib(libraryName: String) {
    implementation(files("${rootProject.rootDir}/libs/$libraryName.jar"))
}

dependencies {
    implementation("commons-io:commons-io")

    implementation("org.apache.commons:commons-configuration2")
    implementation("commons-beanutils:commons-beanutils")

    val asmVersion = "9.7"
    api("org.ow2.asm:asm-tree:$asmVersion")
    implementation("org.ow2.asm:asm:$asmVersion")
    implementation("org.ow2.asm:asm-analysis:$asmVersion")
    implementation("org.ow2.asm:asm-util:$asmVersion")
    implementation("org.ow2.asm:asm-commons:$asmVersion")

    implementation("com.github.leibnitz27:cfr") { isChanging = true }
    implementation("org.vineflower:vineflower:1.11.1")
    implementation("ch.qos.logback:logback-classic:1.5.20")
    implementation("software.coley:cafedude-core:2.6.5")

	//externalLib("fernflower-15-05-20")
}
