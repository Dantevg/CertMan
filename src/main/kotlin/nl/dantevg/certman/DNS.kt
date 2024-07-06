package nl.dantevg.certman

import java.net.URI

object DNS {
	/**
	 * Checks whether the TXT record contains the right challenge, using Google DNS.
	 */
	fun checkTXT(domain: String, challenge: String): Boolean {
		val url = URI("https://dns.google/resolve?name=$domain&type=TXT").toURL()
		return url.readText().contains(challenge)
	}
}
