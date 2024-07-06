package nl.dantevg.certman

import org.bukkit.plugin.java.JavaPlugin

object CertManPlugin : JavaPlugin() {
	override fun onEnable() {
		dataFolder.mkdirs()
		saveDefaultConfig()
	}
}
