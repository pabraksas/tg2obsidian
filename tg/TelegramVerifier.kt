@JsonIgnoreProperties(ignoreUnknown = true)
data class TelegramAuthRequestDTO(
    @JsonProperty("auth_date")
    val authDate: Long,

    @JsonProperty("first_name")
    val firstName: String?,

    @JsonProperty("last_name")
    val lastName: String?,

    val hash: String,

    @JsonProperty("id")
    val telegramId: Long,

    @JsonProperty("photo_url")
    val photoUrl: String?,

    val username: String?
)

fun Any.forceSerialize(separator: String, sorted: Boolean = false): String {
    var fieldNameToAnnotatedNameMap = this.javaClass.declaredFields.map { it.name }.associateWith { fieldName ->
        val jsonFieldName =
            this::class.primaryConstructor?.parameters?.first { it.name == fieldName }?.annotations?.firstOrNull { it is JsonProperty }
        val serializedName = if (jsonFieldName != null) (jsonFieldName as JsonProperty).value else fieldName
        serializedName
    }
    if (sorted)
        fieldNameToAnnotatedNameMap = fieldNameToAnnotatedNameMap.toList().sortedBy { (_, value) -> value}.toMap()
    return fieldNameToAnnotatedNameMap.entries.joinToString(separator) { e ->
        val field = this::class.memberProperties.first { it.name == e.key }
        "${e.value}=${field.javaGetter?.invoke(this)}"
    }
}

object HashUtils {

  fun String.sha256b(): ByteArray {
      return hashString(this, "SHA-256", bytesOnly=true)
  }

  private fun hashString(input: String, algorithm: String, bytesOnly: Boolean = false): ByteArray {
      return MessageDigest
              .getInstance(algorithm)
              .digest(input.toByteArray())
  }

  fun hex(bytes: ByteArray): String  {
      val DIGITS = "0123456789abcdef".toCharArray()
      return buildString(bytes.size * 2) {
          bytes.forEach { byte ->
              val b = byte.toInt() and 0xFF
              append(DIGITS[b shr 4])
              append(DIGITS[b and 0x0F])
          }
      }
  }

  fun hmac_sha256(data: String, key: ByteArray): ByteArray {
      val hmacSha256: Mac = Mac.getInstance("HmacSHA256")
      hmacSha256.init(SecretKeySpec(key, "HmacSHA256"))
      return hmacSha256.doFinal(data.toByteArray())
  }

}

class TelegramVerifier {

  fun checkTelegramData(payload: TelegramAuthRequestDTO, botToken: String): Boolean {
        val serializedString = payload.forceSerialize("\n", sorted = true)
            .split("\n").filter { !it.startsWith("hash") && !it.contains("null") }.joinToString("\n")
        return HashUtils.hex(HashUtils.hmac_sha256(serializedString, botToken.sha256b())) == payload.hash
  }

}
