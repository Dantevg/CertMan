package nl.dantevg.certman

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.shredzone.acme4j.*
import org.shredzone.acme4j.challenge.Challenge
import org.shredzone.acme4j.challenge.Dns01Challenge
import org.shredzone.acme4j.exception.AcmeException
import org.shredzone.acme4j.util.KeyPairUtils
import java.io.File
import java.security.KeyPair
import java.security.Security
import java.time.Duration
import java.time.Instant
import java.util.*
import kotlin.jvm.optionals.getOrNull

// Code here inspired by:
// https://shredzone.org/maven/acme4j/example.html
// https://github.com/shred/acme4j/blob/master/acme4j-example/src/main/java/org/shredzone/acme4j/example/ClientTest.java

const val CA_URI = "acme://letsencrypt.org"
const val CHAIN_FILENAME = "chain.pem"
const val USER_KEY_FILENAME = "user.key"
const val DOMAIN_KEY_FILENAME = "domain.key"
const val MAX_ATTEMPTS = 50

/**
 * Renews the certificate for the given domain.
 *
 * @param dir the directory to store the keys and certificate
 * @param domain the domain for which to renew the certificate
 * @param email the email address to register with the ACME server
 * @param token the DuckDNS token to use for the DNS challenge
 * @throws AcmeException if something went wrong while ordering a certificate
 */
fun renew(dir: File, domain: String, email: String, token: String) {
	Security.addProvider(BouncyCastleProvider())
	
	val userKeyPair = getKeyPair(dir.resolve(USER_KEY_FILENAME))
	val domainKeyPair = getKeyPair(dir.resolve(DOMAIN_KEY_FILENAME))
	val session = Session(CA_URI)
	val account = getAccount(session, userKeyPair, email)
	
	val order = account.newOrder().domains(domain).create()
	order.authorizations.forEach { authorize(it, token) }
	order.execute(domainKeyPair)
	
	val status = waitForCompletion(order::getStatus, order::fetch)
	if (status != Status.VALID) {
		val reason = order.error.map(Problem::toString).orElse("unknown")
		CertMan.logger.severe("Failed to order certificate: $reason")
		throw AcmeException("Failed to order certificate")
	}
	
	CertMan.logger.info("Successfully received certificate for $domain")
	CertMan.logger.info("Certificate URL: ${order.certificate.location}")
	
	dir.resolve(CHAIN_FILENAME).bufferedWriter().use(order.certificate::writeCertificate)
}

/**
 * Reads a key pair from a file, or creates a new one if it doesn't exist.
 */
private fun getKeyPair(keyFile: File): KeyPair =
	if (keyFile.exists()) {
		KeyPairUtils.readKeyPair(keyFile.bufferedReader())
	} else {
		val userKeyPair = KeyPairUtils.createKeyPair()
		KeyPairUtils.writeKeyPair(userKeyPair, keyFile.bufferedWriter())
		userKeyPair
	}

/**
 * Registers a new account with the ACME server, or reuses an existing one.
 */
private fun getAccount(session: Session, keyPair: KeyPair, email: String): Account {
	val tos = session.metadata.termsOfService.getOrNull()
	// TODO: let user agree to ToS
	tos?.let { CertMan.logger.info("You need to agree to the terms of service: $it") }
	
	val account = AccountBuilder()
		.agreeToTermsOfService()
		.useKeyPair(keyPair)
		.addEmail(email)
		.create(session)
	
	CertMan.logger.info("Registered new user: ${account.location}")
	
	return account
}

/**
 * Authorizes the domain for the certificate.
 *
 * @throws AcmeException if the challenge fails
 */
private fun authorize(auth: Authorization, token: String) {
	CertMan.logger.info("Authorizing ${auth.identifier.domain}")
	
	if (auth.status == Status.VALID) return
	
	dnsChallenge(auth, token) { challenge ->
		if (challenge.status == Status.VALID) return@dnsChallenge
		challenge.trigger()
		
		val status = waitForCompletion(challenge::getStatus, challenge::fetch)
		if (status != Status.VALID) {
			val reason = challenge.error.map(Problem::toString).orElse("unknown")
			CertMan.logger.severe("Challenge failed: $reason\n${challenge.json}")
			throw AcmeException("Challenge failed")
		}
		
		CertMan.logger.info("Challenge successful")
	}
}

/**
 * Performs the DNS-01 challenge. The TXT record is removed after execution.
 *
 * @throws AcmeException if there is no DNS challenge or if adding the TXT record fails
 */
fun dnsChallenge(auth: Authorization, token: String, executeChallenge: (Challenge) -> Unit) {
	val challenge = auth.findChallenge(Dns01Challenge::class.java).getOrNull()
		?: throw AcmeException("No ${Dns01Challenge.TYPE} challenge found")
	
	val domain = Dns01Challenge.toRRName(auth.identifier)
	
	if (!DuckDNS.add(domain, token, challenge.digest)) {
		throw AcmeException("Failed to add TXT DNS record")
	}
	
	waitForCompletion {
		CertMan.logger.info("Checking DNS TXT record")
		if (DNS.checkTXT(domain, challenge.digest)) Status.VALID else Status.UNKNOWN
	}
	
	try {
		executeChallenge(challenge)
	} finally {
		if (!DuckDNS.remove(domain, token)) {
			CertMan.logger.severe("Failed to remove TXT DNS record")
		}
	}
}

/**
 * Waits for the challenge to complete, polling every 3 seconds or waiting until
 * the instant returned by [update].
 *
 * @return the final status of the challenge
 * @throws AcmeException if the process did not complete within [MAX_ATTEMPTS] attempts
 */
private fun waitForCompletion(getStatus: () -> Status, update: () -> Optional<Instant>): Status {
	for (attempt in 1..MAX_ATTEMPTS) {
		val status = getStatus()
		if (status == Status.VALID || status == Status.INVALID) {
			return status
		}
		val retryAfter = update().getOrNull()
			?.let { Duration.between(Instant.now(), it) }
			?: Duration.ofSeconds(3)
		Thread.sleep(retryAfter.toMillis())
	}
	throw AcmeException("Too many attempts")
}

/**
 * Waits for the challenge to complete, polling every 3 seconds.
 *
 * @throws AcmeException if the process did not complete within [MAX_ATTEMPTS] attempts
 */
private fun waitForCompletion(getStatus: () -> Status): Status =
	waitForCompletion(getStatus) { Optional.empty() }
