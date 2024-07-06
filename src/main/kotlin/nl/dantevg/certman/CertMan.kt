package nl.dantevg.certman

import org.bukkit.plugin.java.JavaPlugin

object CertMan : JavaPlugin() {
	override fun onEnable() {
		dataFolder.mkdirs()
		saveDefaultConfig()
	}
}
