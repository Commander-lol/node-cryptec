const crypto = require('crypto')
/**
 * Creates a simple wrapper around the `crypto` module to remove the
 * boilerplate commonly needed to encrypt and decrypt values in the
 * common use case
 *
 * The Cryptec class operates by binding methods in the constructor for
 * two reasons:
 * 1. You can easily pass the encrypt and decrypt methods as parameters
 *    to another function if, for example, you need to encrypt an array
 *    of values with `.map`
 * 2. You can reasonably include the Cryptec instance in other objects
 *    and not have to worry about it being included in logs and leaking
 *    the secret used, as the secret is never stored on the instance.
 * @type {Cryptec}
 */
module.exports = class Cryptec {
	constructor(secret, algorithm = 'aes-256-ctr') {
		/**
		 * Take either a string or a buffer and encrypt it
		 * @param object
		 * @returns {*}
		 */
		this.encrypt = object => {
			const cipher = crypto.createCipher(algorithm, secret)
			if (object instanceof Buffer) {
				return Buffer.concat([cipher.update(object, cipher.final())])
			} else {
				return cipher.update(object, 'utf8', 'hex') + cipher.final('hex')
			}
		}

		/**
		 * Run the encrypt function asynchronously, either taking a callback or
		 * (if no callback is provided) returning a promise
		 * @param object
		 * @param cb
		 * @returns {Promise}
		 */
		this.encryptAsync = (object, cb) => {
			if (cb == null) {
				return new Promise((rs, rj) => {
					process.nextTick(() => {
						try {
							const val = this.encrypt(object)
							rs(val)
						} catch(e) {
							rj(e)
						}
					})
				})
			} else {
				process.nextTick(() => {
					try {
						const val = this.encrypt(object)
						cb(null, val)
					} catch(e) {
						cb(e, null)
					}
				})
			}
		}

		/**
		 * Decrypt a previously encrypted value. Cannot use content
		 * inspection to determine the return type, so will return
		 * a string unless `asBuffer` is set to true
		 * @param encrypted
		 * @param asBuffer If true, will decrypt to a buffer. Otherwise
		 * a string will be returned
		 */
		this.decrypt = (encrypted, asBuffer = false) => {
			const decipher = crypto.createDecipher(algorithm, secret)
			if (asBuffer) {
				return Buffer.concat([decipher.update(encrypted), decipher.final()])
			} else {
				return decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8')
			}
		}

		/**
		 * Run the decrypt function asynchronously, either taking a callback or
		 * (if no callback is provided) returning a promise
		 * @param encrypted
		 * @param asBuffer
		 * @param cb
		 * @returns {Promise}
		 */
		this.decryptAsync = (encrypted, asBuffer = false, cb) => {
			if (cb == null) {
				return new Promise((rs, rj) => {
					process.nextTick(() => {
						try {
							const val = this.decrypt(encrypted, asBuffer)
							rs(val)
						} catch(e) {
							rj(e)
						}
					})
				})
			} else {
				process.nextTick(() => {
					try {
						const val = this.decrypt(encrypted, asBuffer)
						cb(null, val)
					} catch(e) {
						cb(e, null)
					}
				})
			}
		}
	}
}