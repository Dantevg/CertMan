package nl.dantevg.certman

import org.bukkit.plugin.java.JavaPlugin

class CertMan : JavaPlugin() {
	override fun onEnable() {
		dataFolder.mkdirs()
		saveDefaultConfig()
		
		
	}
}