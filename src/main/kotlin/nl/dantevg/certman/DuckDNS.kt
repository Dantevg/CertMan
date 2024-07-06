package nl.dantevg.certman

import java.net.URI

private const val BASE_URL = "https://www.duckdns.org/update"

private val domainRegex = """^(?:_acme-challenge\.)?([a-z0-9-]+)\.duckdns\.org""".toRegex()

private fun getSubdomain(domain: String): String? = domainRegex.find(domain)?.value

object DuckDNS {
	fun add(domain: String, token: String, txt: String): Boolean {
		val subdomain = getSubdomain(domain)
		val url = URI("$BASE_URL?domains=$subdomain&token=$token&txt=$txt").toURL()
		val result = url.readText()
		if (result != "OK") {
			CertMan.logger.severe("Error setting DNS TXT record, got response '$result'")
		}
		return result == "OK"
	}
	
	fun remove(domain: String, token: String): Boolean {
		val subdomain = getSubdomain(domain)
		val url = URI("$BASE_URL?domains=$subdomain&token=$token&txt=&clear=true").toURL()
		val result = url.readText()
		if (result != "OK") {
			CertMan.logger.warning("Error removing DNS TXT record, got response '$result'")
		}
		return result == "OK"
	}
}
