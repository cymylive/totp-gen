package com.cymylive.totpgen

import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object Totp {

    /** Base32 解码，容错大小写、空格、连字符、缺省 padding */
    fun base32Decode(input: String): ByteArray {
        val s = input.trim().replace(" ", "").replace("-", "").uppercase().trimEnd('=')
        require(s.isNotEmpty()) { "secret 为空" }
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        var buffer = 0
        var bitsLeft = 0
        val out = ArrayList<Byte>(s.length * 5 / 8)
        for (c in s) {
            val v = alphabet.indexOf(c)
            require(v >= 0) { "非法的 Base32 字符：$c" }
            buffer = (buffer shl 5) or v
            bitsLeft += 5
            if (bitsLeft >= 8) {
                out.add(((buffer shr (bitsLeft - 8)) and 0xFF).toByte())
                bitsLeft -= 8
            }
        }
        return out.toByteArray()
    }

    /** RFC 4226 HOTP */
    fun hotp(key: ByteArray, counter: Long, digits: Int = 6): String {
        val msg = ByteBuffer.allocate(8).putLong(counter).array()
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(key, "HmacSHA1"))
        val digest = mac.doFinal(msg)
        val offset = digest[digest.size - 1].toInt() and 0x0F
        val code = ((digest[offset].toInt() and 0x7F) shl 24) or
                ((digest[offset + 1].toInt() and 0xFF) shl 16) or
                ((digest[offset + 2].toInt() and 0xFF) shl 8) or
                (digest[offset + 3].toInt() and 0xFF)
        val mod = when (digits) {
            8 -> 100_000_000
            else -> 1_000_000
        }
        return (code % mod).toString().padStart(digits, '0')
    }

    /** RFC 6238 TOTP */
    fun totp(secret: String, atMillis: Long = System.currentTimeMillis(), period: Int = 30, digits: Int = 6): String {
        val key = base32Decode(secret)
        return hotp(key, atMillis / 1000 / period, digits)
    }

    fun remainingSeconds(period: Int = 30): Int {
        val now = System.currentTimeMillis() / 1000
        return (period - (now % period)).toInt()
    }

    /** 解析 otpauth:// 链接，返回 (名称, secret, digits, period) 或 null */
    fun parseOtpAuth(uri: String): OtpAuthInfo? {
        if (!uri.trim().lowercase().startsWith("otpauth://")) return null
        return try {
            val u = java.net.URI(uri.trim())
            if (!u.scheme.equals("otpauth", true)) return null
            val label = java.net.URLDecoder.decode(u.path.trimStart('/'), "UTF-8")
            val params = HashMap<String, String>()
            u.rawQuery?.split("&")?.forEach { pair ->
                val i = pair.indexOf('=')
                if (i > 0) {
                    val k = java.net.URLDecoder.decode(pair.substring(0, i), "UTF-8")
                    val v = java.net.URLDecoder.decode(pair.substring(i + 1), "UTF-8")
                    params[k] = v
                }
            }
            val secret = params["secret"]?.trim() ?: return null
            if (secret.isEmpty()) return null
            OtpAuthInfo(
                name = label.ifEmpty { "未命名" },
                secret = secret,
                digits = params["digits"]?.toIntOrNull()?.takeIf { it == 6 || it == 8 } ?: 6,
                period = params["period"]?.toIntOrNull()?.takeIf { it > 0 } ?: 30
            )
        } catch (e: Exception) {
            null
        }
    }
}

data class OtpAuthInfo(val name: String, val secret: String, val digits: Int, val period: Int)
