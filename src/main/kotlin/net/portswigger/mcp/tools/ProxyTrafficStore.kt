package net.portswigger.mcp.tools

/**
 * Bounded, thread-safe store of ORIGINAL proxy requests — the request exactly as received from
 * the client, before Burp match/replace rules and manual Proxy edits are applied.
 *
 * Burp's [burp.api.montoya.proxy.ProxyHttpRequestResponse] only retains `finalRequest()` (the
 * modified request that was actually sent); it has no `originalRequest()`. The original is therefore
 * captured live from a `ProxyRequestHandler.handleRequestReceived` callback (see ExtensionBase) and
 * stashed here keyed by the proxy message id, then looked up when serving a history item.
 *
 * Correlation caveat: history items expose `id()` (not `messageId()`); in Burp these are the same
 * monotonic counter, so lookups use `id()`. Callers must treat a null result as "original not
 * available" and fall back to the modified request rather than assuming the two never match.
 *
 * Entries are LRU-evicted (access-order) to bound memory under high proxy volume. Only requests
 * proxied while the extension is running are captured — history that predates load has no original.
 */
object ProxyTrafficStore {
    private const val MAX_ENTRIES = 5_000

    private val originalRequests = object : LinkedHashMap<Int, String>(1024, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Int, String>?): Boolean =
            size > MAX_ENTRIES
    }

    @Synchronized
    fun recordOriginalRequest(messageId: Int, request: String) {
        originalRequests[messageId] = request
    }

    @Synchronized
    fun originalRequest(messageId: Int): String? = originalRequests[messageId]

    @Synchronized
    fun clear() = originalRequests.clear()
}
