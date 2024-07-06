import kr.entree.spigradle.kotlin.spigot
import kr.entree.spigradle.kotlin.spigotmc
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
	idea
	kotlin("jvm") version "2.0.0"
	id("kr.entree.spigradle") version "2.4.3"
}

group = "nl.dantevg"
version = "1.0-SNAPSHOT"
java.sourceCompatibility = JavaVersion.VERSION_1_8

repositories {
	mavenCentral()
	mavenLocal()
	spigotmc()
}

dependencies {
	testImplementation(kotlin("test"))
	compileOnly(spigot("1.13.2"))
}

tasks.test {
	useJUnitPlatform()
}

kotlin {
	jvmToolchain(21)
	compilerOptions {
		jvmTarget.set(JvmTarget.JVM_1_8)
	}
}

spigot {
	apiVersion = "1.13"
	description = "Automatically manage TLS certificates"
	authors = listOf("RedPolygon")
}