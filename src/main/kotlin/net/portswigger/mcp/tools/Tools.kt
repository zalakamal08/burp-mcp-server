package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.CrawlConfiguration
import burp.api.montoya.sitemap.SiteMapFilter
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.HistoryAccessSecurity
import net.portswigger.mcp.security.HistoryAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import java.awt.Component
import java.awt.Container
import java.awt.EventQueue
import java.awt.KeyboardFocusManager
import java.util.regex.Pattern
import javax.swing.AbstractButton
import javax.swing.JCheckBox
import javax.swing.JLabel
import javax.swing.JTabbedPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.SwingUtilities

private suspend fun checkHistoryPermissionOrDeny(
    accessType: HistoryAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
): Boolean {
    val allowed = HistoryAccessSecurity.checkHistoryAccessPermission(accessType, config)
    if (!allowed) {
        api.logging().logToOutput("MCP $logMessage access denied")
        return false
    }
    api.logging().logToOutput("MCP $logMessage access granted")
    return true
}

private fun truncateIfNeeded(serialized: String): String {
    return if (serialized.length > 5000) {
        serialized.substring(0, 5000) + "... (truncated)"
    } else {
        serialized
    }
}

// Writes a diagnostic line to Burp's extension Output, but only when the user has
// enabled "Debug logging" in the MCP config tab. Use for verbose tracing that would
// otherwise spam the Output (e.g. the Repeater Send-button path).
private fun debugLog(config: McpConfig, api: MontoyaApi, message: String) {
    if (config.debugLogging) api.logging().logToOutput("[MCP debug] $message")
}

// Normalizes any mix of \r\n, \r, or \n into proper HTTP CRLF line endings.
// JSON transport can deliver line endings inconsistently; Burp needs real CRLF
// to parse a raw HTTP request, so we normalize before handing requests off.
private fun normalizeHttpLineEndings(raw: String): String =
    raw.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")

// Splits a raw HTTP message into (headerSection, body) at the first blank line.
// Tolerates CRLF (\r\n\r\n) and LF-only (\n\n) separators; if no blank line is
// found, the whole message is treated as headers and the body is empty.
private fun splitHttpHeadersAndBody(message: String): Pair<String, String> {
    val crlf = message.indexOf("\r\n\r\n")
    if (crlf >= 0) return message.substring(0, crlf) to message.substring(crlf + 4)
    val lf = message.indexOf("\n\n")
    if (lf >= 0) return message.substring(0, lf) to message.substring(lf + 2)
    return message to ""
}

// Truncates a response string to maxChars, preserving the status line + headers
// (which come first) and appending a note with the full length. A non-positive
// maxChars disables truncation.
private fun truncateResponse(response: String, maxChars: Int): String {
    if (maxChars <= 0 || response.length <= maxChars) return response
    return response.substring(0, maxChars) +
        "\n\n[response truncated at $maxChars chars, full length: ${response.length}. " +
        "Pass a larger maxResponseChars to see more.]"
}

fun Server.registerTools(api: MontoyaApi, config: McpConfig) {
    val disabledSet = config.getDisabledToolsList()
    fun enabled(name: String) = name !in disabledSet

    if (enabled("send_http1_request")) mcpTool<SendHttp1Request>("Issues an HTTP/1.1 request and returns the response.") {
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/1.1 request: $targetHostname:$targetPort")

        val fixedContent = content.replace("\r", "").replace("\n", "\r\n")

        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        val response = api.http().sendRequest(request)

        response?.toString() ?: "<no response>"
    }

    if (enabled("send_http2_request")) mcpTool<SendHttp2Request>("Issues an HTTP/2 request and returns the response. Do NOT pass headers to the body parameter.") {
        val http2RequestDisplay = buildString {
            pseudoHeaders.forEach { (key, value) ->
                val headerName = if (key.startsWith(":")) key else ":$key"
                appendLine("$headerName: $value")
            }
            headers.forEach { (key, value) ->
                appendLine("$key: $value")
            }
            if (requestBody.isNotBlank()) {
                appendLine()
                append(requestBody)
            }
        }

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, http2RequestDisplay, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/2 request: $targetHostname:$targetPort")

        val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")

        val fixedPseudoHeaders = LinkedHashMap<String, String>().apply {
            orderedPseudoHeaderNames.forEach { name ->
                val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
                if (value != null) {
                    put(name, value)
                }
            }

            pseudoHeaders.forEach { (key, value) ->
                val properKey = if (key.startsWith(":")) key else ":$key"
                if (!containsKey(properKey)) {
                    put(properKey, value)
                }
            }
        }

        val headerList = (fixedPseudoHeaders + headers).map { HttpHeader.httpHeader(it.key.lowercase(), it.value) }

        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        val response = api.http().sendRequest(request, HttpMode.HTTP_2)

        response?.toString() ?: "<no response>"
    }

    if (enabled("create_repeater_tab")) mcpTool<CreateRepeaterTab>("Creates a new Repeater tab with the specified HTTP request and optional tab name. Line endings are normalized to HTTP CRLF automatically, so \\n in the content is accepted. The tab is targeted at the given targetHostname/targetPort/usesHttps.") {
        val request = HttpRequest.httpRequest(toMontoyaService(), normalizeHttpLineEndings(content))
        api.repeater().sendToRepeater(request, tabName)
    }

    if (enabled("send_to_intruder")) mcpTool<SendToIntruder>("Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. Line endings are normalized to HTTP CRLF automatically.") {
        val request = HttpRequest.httpRequest(toMontoyaService(), normalizeHttpLineEndings(content))
        api.intruder().sendToIntruder(request, tabName)
    }

    if (enabled("url_encode")) mcpTool<UrlEncode>("URL encodes the input string") {
        api.utilities().urlUtils().encode(content)
    }

    if (enabled("url_decode")) mcpTool<UrlDecode>("URL decodes the input string") {
        api.utilities().urlUtils().decode(content)
    }

    if (enabled("base64_encode")) mcpTool<Base64Encode>("Base64 encodes the input string") {
        api.utilities().base64Utils().encodeToString(content)
    }

    if (enabled("base64_decode")) mcpTool<Base64Decode>("Base64 decodes the input string") {
        api.utilities().base64Utils().decode(content).toString()
    }

    if (enabled("generate_random_string")) mcpTool<GenerateRandomString>("Generates a random string of specified length and character set") {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    if (enabled("output_project_options")) mcpTool(
        "output_project_options",
        "Outputs current project-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        api.burpSuite().exportProjectOptionsAsJson()
    }

    if (enabled("output_user_options")) mcpTool(
        "output_user_options",
        "Outputs current user-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        api.burpSuite().exportUserOptionsAsJson()
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'"

    if (enabled("set_project_options")) mcpTool<SetProjectOptions>("Sets project-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'user_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting project-level configuration: $json")
            api.burpSuite().importProjectOptionsFromJson(json)

            "Project configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }


    if (enabled("set_user_options")) mcpTool<SetUserOptions>("Sets user-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'project_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting user-level configuration: $json")
            api.burpSuite().importUserOptionsFromJson(json)

            "User configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        if (enabled("get_scanner_issues")) mcpPaginatedTool<GetScannerIssues>("Displays information about issues identified by the scanner") {
            api.siteMap().issues().asSequence().map { Json.encodeToString(it.toSerializableForm()) }
        }

        val collaboratorClient by lazy { api.collaborator().createClient() }

        if (enabled("generate_collaborator_payload")) mcpTool<GenerateCollaboratorPayload>(
            "Generates a Burp Collaborator payload URL for out-of-band (OOB) testing. " +
            "Inject this payload into requests to detect server-side interactions (DNS lookups, HTTP requests, SMTP). " +
            "Use get_collaborator_interactions with the returned payloadId to check for interactions."
        ) {
            api.logging().logToOutput("MCP generating Collaborator payload${customData?.let { " with custom data" } ?: ""}")

            val payload = if (customData != null) {
                collaboratorClient.generatePayload(customData)
            } else {
                collaboratorClient.generatePayload()
            }

            val server = collaboratorClient.server()
            "Payload: $payload\nPayload ID: ${payload.id()}\nCollaborator server: ${server.address()}"
        }

        if (enabled("get_collaborator_interactions")) mcpTool<GetCollaboratorInteractions>(
            "Polls Burp Collaborator for out-of-band interactions (DNS, HTTP, SMTP). " +
            "Optionally filter by payloadId from generate_collaborator_payload. " +
            "Returns interaction details including type, timestamp, client IP, and protocol-specific data."
        ) {
            api.logging().logToOutput("MCP polling Collaborator interactions${payloadId?.let { " for payload: $it" } ?: ""}")

            val interactions = if (payloadId != null) {
                collaboratorClient.getInteractions(InteractionFilter.interactionIdFilter(payloadId))
            } else {
                collaboratorClient.getAllInteractions()
            }

            if (interactions.isEmpty()) {
                "No interactions detected"
            } else {
                interactions.joinToString("\n\n") {
                    Json.encodeToString(it.toSerializableForm())
                }
            }
        }

        if (enabled("start_active_scan")) mcpTool<StartActiveScan>(
            "Starts an active vulnerability scan on the given HTTP request using the Burp Scanner. " +
            "Sends the request first to capture a baseline response, then passes it to the scanner. " +
            "Use get_scanner_issues to poll for discovered vulnerabilities. Pro only."
        ) {
            api.logging().logToOutput("MCP starting active scan (crawl): $targetHostname:$targetPort")
            val scheme = if (usesHttps) "https" else "http"
            val portSuffix = if ((usesHttps && targetPort == 443) || (!usesHttps && targetPort == 80)) "" else ":$targetPort"
            val targetUrl = "$scheme://$targetHostname$portSuffix/"
            api.scanner().startCrawl(CrawlConfiguration.crawlConfiguration(targetUrl))
            "Active crawl+audit started for $targetUrl. Use get_scanner_issues to poll for results."
        }

        if (enabled("start_passive_scan")) mcpTool<StartPassiveScan>(
            "Runs passive vulnerability checks on the given HTTP request without sending additional requests. " +
            "Sends the request once to obtain a response, then runs Burp passive scan checks on the pair. " +
            "Passive checks detect issues like missing security headers, information disclosure, and insecure cookies. " +
            "Use get_scanner_issues to view results. Pro only."
        ) {
            api.logging().logToOutput("MCP adding to sitemap for passive analysis: $targetHostname:$targetPort")
            val fixedContent = content.replace("\r", "").replace("\n", "\r\n")
            val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
            val requestResponse = api.http().sendRequest(request)
            api.siteMap().add(requestResponse)
            "Request added to sitemap for $targetHostname:$targetPort. " +
            "Burp's passive scanner will automatically analyse it. Use get_scanner_issues to view results."
        }
    }

    if (enabled("get_proxy_http_history")) mcpPaginatedTool<GetProxyHttpHistory>("Displays items within the proxy HTTP history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        api.proxy().history().asSequence().map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    if (enabled("get_proxy_http_history_regex")) mcpPaginatedTool<GetProxyHttpHistoryRegex>("Displays items matching a specified regex within the proxy HTTP history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().history { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    if (enabled("get_proxy_websocket_history")) mcpPaginatedTool<GetProxyWebsocketHistory>("Displays items within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        api.proxy().webSocketHistory().asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    if (enabled("get_proxy_websocket_history_regex")) mcpPaginatedTool<GetProxyWebsocketHistoryRegex>("Displays items matching a specified regex within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().webSocketHistory { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    // -------------------------------------------------------------------------
    // History by index
    // -------------------------------------------------------------------------

    if (enabled("get_proxy_http_history_item")) mcpTool<GetProxyHttpHistoryItem>(
        "Returns a single proxy HTTP history entry by its zero-based index. " +
        "Use get_proxy_http_history to discover valid indices."
    ) {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) return@mcpTool "HTTP history access denied by Burp Suite"

        val history = api.proxy().history()
        if (index < 0 || index >= history.size) {
            return@mcpTool "Index $index is out of range. History contains ${history.size} item(s)."
        }
        truncateIfNeeded(Json.encodeToString(history[index].toSerializableForm()))
    }

    // -------------------------------------------------------------------------
    // Scope
    // -------------------------------------------------------------------------

    if (enabled("is_in_scope")) mcpTool<IsInScope>("Checks whether a URL is within the Burp Suite target scope.") {
        val inScope = api.scope().isInScope(url)
        if (inScope) "In scope: $url" else "NOT in scope: $url"
    }

    if (enabled("add_to_scope")) mcpTool<AddToScope>("Adds a URL to the Burp Suite target scope.") {
        api.scope().includeInScope(url)
        "Added to scope: $url"
    }

    if (enabled("remove_from_scope")) mcpTool<RemoveFromScope>("Removes a URL from the Burp Suite target scope.") {
        api.scope().excludeFromScope(url)
        "Removed from scope: $url"
    }

    // -------------------------------------------------------------------------
    // Site map
    // -------------------------------------------------------------------------

    if (enabled("get_site_map")) mcpPaginatedTool<GetSiteMap>("Returns paginated entries from the Burp Suite target sitemap.") {
        api.siteMap().requestResponses().asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    if (enabled("get_site_map_for_url")) mcpPaginatedTool<GetSiteMapForUrl>(
        "Returns paginated sitemap entries whose URL starts with the given prefix. " +
        "Useful for drilling into a specific host or path."
    ) {
        api.siteMap().requestResponses(SiteMapFilter.prefixFilter(url)).asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    if (enabled("set_task_execution_engine_state")) mcpTool<SetTaskExecutionEngineState>("Sets the state of Burp's task execution engine (paused or unpaused)") {
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED

        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    if (enabled("set_proxy_intercept_state")) mcpTool<SetProxyInterceptState>("Enables or disables Burp Proxy Intercept") {
        if (intercepting) {
            api.proxy().enableIntercept()
        } else {
            api.proxy().disableIntercept()
        }

        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    // -------------------------------------------------------------------------
    // Response extraction
    // -------------------------------------------------------------------------

    if (enabled("extract_from_response")) mcpTool<ExtractFromResponse>(
        "Extracts all regex matches from an HTTP response string. " +
        "Use 'group' to select a specific capture group (0 = entire match, 1+ = numbered group). " +
        "Useful for pulling out CSRF tokens, auth values, redirect URLs, or any pattern from a response. " +
        "The response can come from send_http1_request, send_http2_request, or any history tool."
    ) {
        val compiled = try {
            Pattern.compile(regex, Pattern.DOTALL)
        } catch (e: Exception) {
            return@mcpTool "Invalid regex: ${e.message}"
        }

        val matcher = compiled.matcher(response)
        val results = mutableListOf<String>()

        while (matcher.find()) {
            if (group > matcher.groupCount()) {
                return@mcpTool "Group $group does not exist — the regex has ${matcher.groupCount()} capture group(s)."
            }
            results.add(matcher.group(group) ?: "")
        }

        if (results.isEmpty()) "No matches found" else results.joinToString("\n")
    }

    // -------------------------------------------------------------------------
    // Proxy history search
    // -------------------------------------------------------------------------

    if (enabled("search_proxy_history")) mcpPaginatedTool<SearchProxyHistory>(
        "Searches proxy HTTP history with optional filters combined with AND logic. " +
        "statusCode: exact HTTP status code (200, 302, 401, …). " +
        "method: HTTP verb, case-insensitive (GET, POST, PUT, …). " +
        "contentType: substring match on the Content-Type response header (json, html, xml, …). " +
        "bodyKeyword: case-insensitive substring search in the response body only. " +
        "Omit any filter to match all values for that field."
    ) {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history search")
        }
        if (!allowed) return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")

        api.proxy().history().asSequence().filter { item ->
            val reqStr = item.request().toString()
            val respStr = item.response()?.toString() ?: ""
            val (headerSection, body) = splitHttpHeadersAndBody(respStr)

            // Method: first whitespace-delimited token of the request line ("GET / HTTP/1.1" → "GET")
            if (method != null) {
                val parsedMethod = reqStr.trimStart().split(Regex("\\s+")).firstOrNull() ?: ""
                if (!parsedMethod.equals(method, ignoreCase = true)) return@filter false
            }

            // Status code: second whitespace-delimited token of the status line ("HTTP/1.1 200 OK" → 200)
            if (statusCode != null) {
                val parsedStatus = respStr.lineSequence().firstOrNull()
                    ?.trim()?.split(Regex("\\s+"))?.getOrNull(1)?.toIntOrNull()
                if (parsedStatus != statusCode) return@filter false
            }

            // Content-Type: header section only (before the blank line)
            if (contentType != null) {
                val hasMatch = headerSection.lineSequence().any { line ->
                    line.startsWith("Content-Type:", ignoreCase = true) &&
                    line.contains(contentType, ignoreCase = true)
                }
                if (!hasMatch) return@filter false
            }

            // Body keyword: response body only (after the blank line)
            if (bodyKeyword != null) {
                if (!body.contains(bodyKeyword, ignoreCase = true)) return@filter false
            }

            true
        }.map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    // -------------------------------------------------------------------------
    // Repeater tabs
    // -------------------------------------------------------------------------

    if (enabled("list_repeater_tabs")) mcpTool("list_repeater_tabs", "Lists all tabs currently open in Burp Suite's Repeater. Returns each tab's zero-based index and display name so you can reference them by index in other Repeater tools.") {
        val tabs = repeaterTabs(api)
        if (tabs.isEmpty()) {
            "No Repeater tabs found. Make sure Burp's Repeater tab has been opened at least once."
        } else {
            tabs.joinToString("\n") { (index, name) -> "Index $index: $name" }
        }
    }

    if (enabled("get_repeater_tab")) mcpTool<GetRepeaterTab>(
        "Returns the request currently loaded in a Repeater tab and its resolved target (host/port/HTTPS, auto-detected). " +
        "Use this to read a request the user set up, then send it (optionally modified) with send_repeater_tab_request. " +
        "Also returns the response currently shown in the tab's panel, which reflects the user's last MANUAL send in " +
        "Burp (agent sends do not render there — Burp's API has no way to push a response into a tab). " +
        "Override detection with targetHostname/targetPort/usesHttps. Truncated to maxResponseChars (default 50000). " +
        "Use list_repeater_tabs to discover tab indices."
    ) {
        val info = repeaterTabConnectionInfo(tabIndex, api)
            ?: return@mcpTool "Could not read Repeater tab $tabIndex. Verify the index is valid and the tab contains a request."

        val host = targetHostname ?: info.hostname
        val port = targetPort ?: info.port
        val https = usesHttps ?: info.usesHttps
        val targetLine = if (host != null && port != null) {
            "${if (https == true) "https" else "http"}://$host:$port"
        } else {
            "(target could not be auto-detected — pass targetHostname/targetPort/usesHttps when sending)"
        }

        val responseText = repeaterTabResponseText(tabIndex, api) ?: "(no response in the tab's panel)"
        buildString {
            appendLine("=== TARGET ===")
            appendLine(targetLine)
            appendLine()
            appendLine("=== REQUEST ===")
            appendLine(info.request)
            appendLine("=== RESPONSE (tab panel — user's last manual send) ===")
            append(truncateResponse(responseText, maxResponseChars))
        }
    }

    if (enabled("send_repeater_tab_request")) mcpTool<SendRepeaterTabRequest>(
        "Sends a Repeater tab's request through Burp's HTTP engine and returns the response. " +
        "The target (host/port/HTTPS) is auto-detected from the tab; pass the optional 'request' field to send a " +
        "MODIFIED request instead of the one in the tab (ideal for fuzzing, e.g. change /user/1 to /user/2). " +
        "Override the target with targetHostname/targetPort/usesHttps if needed. " +
        "Large responses are truncated to maxResponseChars (default 50000). " +
        "Note: the response is returned here; it does not render inside the Repeater tab (Burp's API has no way to " +
        "push a response into a tab). The request is visible in Burp's Logger. Use list_repeater_tabs to find indices."
    ) {
        val info = repeaterTabConnectionInfo(tabIndex, api)
            ?: return@mcpTool "Could not read Repeater tab $tabIndex. Verify the index is valid and the tab contains a request."

        val requestToSend = request ?: info.request
        val host = targetHostname ?: info.hostname
        val port = targetPort ?: info.port
        val https = usesHttps ?: info.usesHttps ?: false
        debugLog(config, api, "send_repeater_tab_request: tab=$tabIndex inlineRequest=${request != null} " +
            "resolved host=$host port=$port https=$https")

        if (host == null || port == null) {
            return@mcpTool "Could not determine the target for Repeater tab $tabIndex. " +
                "Pass targetHostname, targetPort, and usesHttps explicitly."
        }

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(host, port, config, requestToSend, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP Repeater tab $tabIndex request denied: $host:$port")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP sending Repeater tab $tabIndex: ${if (https) "https" else "http"}://$host:$port")
        val fixedRequest = normalizeHttpLineEndings(requestToSend)
        val httpRequest = HttpRequest.httpRequest(HttpService.httpService(host, port, https), fixedRequest)
        val response = api.http().sendRequest(httpRequest)
        truncateResponse(response?.toString() ?: "<no response>", maxResponseChars)
    }

    if (enabled("get_active_editor_contents")) mcpTool("get_active_editor_contents", "Outputs the contents of the user's active message editor") {
        getActiveEditor(api)?.text ?: "<No active editor>"
    }

    if (enabled("set_active_editor_contents")) mcpTool<SetActiveEditorContents>("Sets the content of the user's active message editor") {
        val editor = getActiveEditor(api) ?: return@mcpTool "<No active editor>"

        if (!editor.isEditable) {
            return@mcpTool "<Current editor is not editable>"
        }

        editor.text = text

        "Editor text has been set"
    }
}

fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()

    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner

    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }

    return if (isInBurpWindow && permanentFocusOwner is JTextArea) {
        permanentFocusOwner
    } else {
        null
    }
}

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(): HttpService = HttpService.httpService(targetHostname, targetPort, usesHttps)
}

@Serializable
data class SendHttp1Request(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTab(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class UrlEncode(val content: String)

@Serializable
data class UrlDecode(val content: String)

@Serializable
data class Base64Encode(val content: String)

@Serializable
data class Base64Decode(val content: String)

@Serializable
data class GenerateRandomString(val length: Int, val characterSet: String)

@Serializable
data class SetProjectOptions(val json: String)

@Serializable
data class SetUserOptions(val json: String)

@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetActiveEditorContents(val text: String)

@Serializable
data class GetScannerIssues(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(val regex: String, override val count: Int, override val offset: Int) :
    Paginated

@Serializable
data class GenerateCollaboratorPayload(
    val customData: String? = null
)

@Serializable
data class GetCollaboratorInteractions(
    val payloadId: String? = null
)

@Serializable
data class StartActiveScan(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class GetProxyHttpHistoryItem(val index: Int)

@Serializable
data class IsInScope(val url: String)

@Serializable
data class AddToScope(val url: String)

@Serializable
data class RemoveFromScope(val url: String)

@Serializable
data class GetSiteMap(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetSiteMapForUrl(
    val url: String,
    override val count: Int,
    override val offset: Int
) : Paginated

@Serializable
data class StartPassiveScan(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class GetRepeaterTab(
    val tabIndex: Int,
    val targetHostname: String? = null,
    val targetPort: Int? = null,
    val usesHttps: Boolean? = null,
    val maxResponseChars: Int = 50000
)

@Serializable
data class SendRepeaterTabRequest(
    val tabIndex: Int,
    val request: String? = null,
    val targetHostname: String? = null,
    val targetPort: Int? = null,
    val usesHttps: Boolean? = null,
    val maxResponseChars: Int = 50000
)

@Serializable
data class ExtractFromResponse(
    val response: String,
    val regex: String,
    val group: Int = 0
)

@Serializable
data class SearchProxyHistory(
    val statusCode: Int? = null,
    val method: String? = null,
    val contentType: String? = null,
    val bodyKeyword: String? = null,
    override val count: Int,
    override val offset: Int
) : Paginated

// ---------------------------------------------------------------------------
// Repeater Swing utilities
// ---------------------------------------------------------------------------

// Target fields are nullable: a tab may be readable (request present) even when
// the target host/port/scheme can't be auto-detected. Callers fall back to
// explicit override parameters in that case.
private data class RepeaterConnectionInfo(
    val request: String,
    val hostname: String?,
    val port: Int?,
    val usesHttps: Boolean?
)

private fun repeaterTabs(api: MontoyaApi): List<Pair<Int, String>> {
    val frame = api.userInterface().swingUtils().suiteFrame()
    val result = mutableListOf<Pair<Int, String>>()
    runOnEdt {
        val pane = findRepeaterInnerTabbedPane(frame) ?: return@runOnEdt
        for (i in 0 until pane.tabCount) {
            val name = pane.getTitleAt(i)
            if (!name.isNullOrBlank() && name != "+") result.add(i to name)
        }
    }
    return result
}

private fun repeaterTabConnectionInfo(tabIndex: Int, api: MontoyaApi): RepeaterConnectionInfo? {
    val frame = api.userInterface().swingUtils().suiteFrame()
    var result: RepeaterConnectionInfo? = null
    runOnEdt {
        val pane = findRepeaterInnerTabbedPane(frame) ?: return@runOnEdt
        if (tabIndex < 0 || tabIndex >= pane.tabCount) return@runOnEdt
        val tabComp = pane.getComponentAt(tabIndex) as? Container ?: return@runOnEdt
        val requestText = findRepeaterRequestArea(tabComp)?.text ?: return@runOnEdt

        // Priority 1: target URL field has the full scheme://host:port
        val targetUrl = findRepeaterTargetUrl(tabComp)
        val fromUrl = targetUrl?.let { parseRepeaterTargetUrl(it) }

        result = if (fromUrl != null) {
            RepeaterConnectionInfo(requestText, fromUrl.first, fromUrl.second, fromUrl.third)
        } else {
            // Priority 2: Host header for host/port; scheme from (in order):
            //   1. an HTTPS/SSL/TLS checkbox (older Burp),
            //   2. the request protocol line — HTTP/2 is always TLS, so "... HTTP/2" ⇒ https,
            //   3. the Host-header port heuristic (443/8443 ⇒ https).
            // Modern Burp has no HTTPS checkbox or URL text field (the target sits behind the
            // "Target:" control), so the HTTP/2 signal is what saves the common case here.
            // Any field may be null — the request is still returned so callers can override.
            val fromHost = deriveTargetFromHostHeader(requestText)
            val httpsFromCheckbox = findRepeaterHttpsState(tabComp)
            val httpsFromProtocol = if (requestUsesHttp2(requestText)) true else null
            val https = httpsFromCheckbox ?: httpsFromProtocol ?: fromHost?.third
            // If we inferred HTTPS but the host header gave no explicit port, prefer 443 over 80.
            val port = fromHost?.second?.let { p ->
                if (https == true && p == 80 && !hostHeaderHasExplicitPort(requestText)) 443 else p
            }
            RepeaterConnectionInfo(requestText, fromHost?.first, port, https)
        }
    }
    return result
}

private fun repeaterTabResponseText(tabIndex: Int, api: MontoyaApi): String? {
    val frame = api.userInterface().swingUtils().suiteFrame()
    var result: String? = null
    runOnEdt {
        val pane = findRepeaterInnerTabbedPane(frame) ?: return@runOnEdt
        if (tabIndex < 0 || tabIndex >= pane.tabCount) return@runOnEdt
        val tabComp = pane.getComponentAt(tabIndex) as? Container ?: return@runOnEdt
        result = findRepeaterResponseArea(tabComp)?.text?.takeIf { it.isNotBlank() }
    }
    return result
}

// Returns the top-level Repeater panel — the container that holds the inner tabbed pane
// of request tabs. (Reading tab content works from here; we no longer drive the toolbar.)
private fun findRepeaterPanel(container: Container): Container? {
    val mainPane = findTabbedPaneContaining(container, "Repeater") ?: return null
    val idx = (0 until mainPane.tabCount)
        .firstOrNull { mainPane.getTitleAt(it).equals("Repeater", ignoreCase = true) } ?: return null
    return mainPane.getComponentAt(idx) as? Container
}

private fun findRepeaterInnerTabbedPane(container: Container): JTabbedPane? {
    val repeaterPanel = findRepeaterPanel(container) ?: return null
    return findFirstTabbedPane(repeaterPanel)
}

private fun findTabbedPaneContaining(container: Container, tabTitle: String): JTabbedPane? {
    val queue = ArrayDeque<Component>()
    queue.add(container)
    while (queue.isNotEmpty()) {
        val comp = queue.removeFirst()
        if (comp is JTabbedPane && (0 until comp.tabCount).any { comp.getTitleAt(it).equals(tabTitle, ignoreCase = true) }) {
            return comp
        }
        if (comp is Container) comp.components.forEach { queue.add(it) }
    }
    return null
}

private fun findFirstTabbedPane(container: Container): JTabbedPane? {
    val queue = ArrayDeque<Component>()
    container.components.forEach { queue.add(it) }
    while (queue.isNotEmpty()) {
        val comp = queue.removeFirst()
        if (comp is JTabbedPane) return comp
        if (comp is Container) comp.components.forEach { queue.add(it) }
    }
    return null
}

private val HTTP_VERBS = listOf("GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE ")

private fun collectTextAreas(container: Container): List<JTextArea> {
    val areas = mutableListOf<JTextArea>()
    val queue = ArrayDeque<Component>()
    queue.add(container)
    while (queue.isNotEmpty()) {
        val comp = queue.removeFirst()
        if (comp is JTextArea) areas.add(comp)
        if (comp is Container) comp.components.forEach { queue.add(it) }
    }
    return areas
}

private fun findRepeaterRequestArea(container: Container): JTextArea? {
    val areas = collectTextAreas(container)
    return areas.firstOrNull { area -> HTTP_VERBS.any { area.text.trimStart().startsWith(it) } }
        ?: areas.firstOrNull { it.isEditable }
}

private fun findRepeaterResponseArea(container: Container): JTextArea? {
    val areas = collectTextAreas(container)
    // Response status line starts with "HTTP/" but is NOT an HTTP verb line
    return areas.firstOrNull { area ->
        val t = area.text.trimStart()
        t.startsWith("HTTP/") && !HTTP_VERBS.any { t.startsWith(it) }
    }
}

// Looks for an HTTPS checkbox or toggle in the tab's Swing tree (Burp labels it "HTTPS", "SSL", or "TLS").
private fun findRepeaterHttpsState(container: Container): Boolean? {
    val queue = ArrayDeque<Component>()
    queue.add(container)
    while (queue.isNotEmpty()) {
        val comp = queue.removeFirst()
        if (comp is JCheckBox) {
            val label = comp.text?.lowercase() ?: ""
            if (label.contains("https") || label.contains("ssl") || label.contains("tls")) {
                return comp.isSelected
            }
        }
        if (comp is Container) comp.components.forEach { queue.add(it) }
    }
    return null
}

// Looks for the tab's target URL anywhere in the component tree. Older Burp showed
// it in a JTextField; modern Burp shows it as a "Target:" label/button. We therefore
// scan JTextField, JLabel, and AbstractButton text for an http(s):// URL.
private fun findRepeaterTargetUrl(container: Container): String? {
    val queue = ArrayDeque<Component>()
    queue.add(container)
    while (queue.isNotEmpty()) {
        val comp = queue.removeFirst()
        val text = when (comp) {
            is JTextField -> comp.text
            is AbstractButton -> comp.text
            is JLabel -> comp.text
            else -> null
        }?.trim()
        if (text != null) {
            val url = extractUrl(text)
            if (url != null) return url
        }
        if (comp is Container) comp.components.forEach { queue.add(it) }
    }
    return null
}

// Pulls the first http(s):// token out of a string (the "Target:" label may read
// "Target: https://host" or wrap the URL in other text).
private fun extractUrl(text: String): String? {
    val idx = text.indexOf("https://").let { if (it >= 0) it else text.indexOf("http://") }
    if (idx < 0) return null
    return text.substring(idx).split(Regex("\\s"))[0].trim()
}

// True when the request's protocol line ends with HTTP/2 (HTTP/2 is always TLS in practice).
private fun requestUsesHttp2(request: String): Boolean {
    val firstLine = request.lineSequence().firstOrNull()?.trim() ?: return false
    return firstLine.endsWith("HTTP/2", ignoreCase = true) ||
           firstLine.endsWith("HTTP/2.0", ignoreCase = true)
}

private fun hostHeaderHasExplicitPort(request: String): Boolean {
    val hostValue = request.lineSequence()
        .firstOrNull { it.trim().startsWith("Host:", ignoreCase = true) }
        ?.substringAfter(":")?.trim() ?: return false
    return hostValue.substringAfterLast(':', "").toIntOrNull() != null
}

private fun parseRepeaterTargetUrl(url: String): Triple<String, Int, Boolean>? {
    return try {
        val https = url.startsWith("https://")
        // Drop the scheme and any path/query so only the host[:port] authority remains.
        val authority = url.removePrefix("https://").removePrefix("http://").substringBefore('/')
        val colonIdx = authority.lastIndexOf(':')
        if (colonIdx >= 0) {
            val host = authority.substring(0, colonIdx)
            val port = authority.substring(colonIdx + 1).toIntOrNull() ?: if (https) 443 else 80
            Triple(host, port, https)
        } else {
            Triple(authority, if (https) 443 else 80, https)
        }
    } catch (_: Exception) { null }
}

private fun deriveTargetFromHostHeader(request: String): Triple<String, Int, Boolean>? {
    val hostValue = request.lines()
        .firstOrNull { it.trim().startsWith("Host:", ignoreCase = true) }
        ?.substringAfter(":")?.trim() ?: return null
    return if (hostValue.contains(":")) {
        val parts = hostValue.split(":")
        val port = parts[1].trim().toIntOrNull() ?: 80
        // Use port to make a best-effort HTTPS guess; caller may override via the HTTPS checkbox
        val httpsGuess = port == 443 || port == 8443
        Triple(parts[0].trim(), port, httpsGuess)
    } else {
        Triple(hostValue, 80, false)
    }
}

private fun runOnEdt(block: () -> Unit) {
    if (EventQueue.isDispatchThread()) {
        block()
    } else {
        try { SwingUtilities.invokeAndWait(block) } catch (_: Exception) {}
    }
}